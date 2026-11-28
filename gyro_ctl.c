/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Private control channel for nfkernel gyro support.
 *
 * No enenkernel ioctl or abi.h entry is added.  A root userspace process
 * sends a small fixed message over NETLINK_USERSOCK; the module updates the
 * target process and x/y angles.  Probe registration is deferred to a
 * workqueue because register_kretprobe() may sleep, while netlink input can
 * run in softirq context.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <net/sock.h>

#include "gyro.h"
#include "gyro_ctl.h"

static struct sock *g_nfk_gyro_nl;
static struct work_struct g_nfk_gyro_work;
static spinlock_t g_nfk_gyro_lock;
static struct nfk_gyro_msg g_nfk_gyro_pending;
static bool g_nfk_gyro_pending_valid;
static bool g_nfk_gyro_exiting;
static bool g_nfk_gyro_ready;

static void nfk_gyro_work_fn(struct work_struct *work)
{
	struct nfk_gyro_msg req;
	bool valid = false;
	unsigned long flags;

	if (!g_nfk_gyro_ready)
		return;
	spin_lock_irqsave(&g_nfk_gyro_lock, flags);
	if (g_nfk_gyro_pending_valid) {
		req = g_nfk_gyro_pending;
		g_nfk_gyro_pending_valid = false;
		valid = true;
	}
	spin_unlock_irqrestore(&g_nfk_gyro_lock, flags);

	if (!valid || READ_ONCE(g_nfk_gyro_exiting))
		return;

	switch (req.cmd) {
	case NFK_GYRO_CMD_SET:
		if (!gyro_sock_active() && gyro_sock_install(req.pid) < 0)
			return;
		gyro_sock_set(req.x_bits, req.y_bits);
		gyro_sock_set_enabled(true);
		break;
	case NFK_GYRO_CMD_STOP:
		gyro_sock_set_enabled(false);
		break;
	case NFK_GYRO_CMD_RESUME:
		if (gyro_sock_active())
			gyro_sock_set_enabled(true);
		break;
	case NFK_GYRO_CMD_REMOVE:
		gyro_sock_remove();
		break;
	default:
		break;
	}
}

static void nfk_gyro_nl_input(struct sk_buff *skb)
{
	struct nlmsghdr *nlh = nlmsg_hdr(skb);
	struct nfk_gyro_msg req;
	unsigned long flags;

	if (!nlh || nlh->nlmsg_len < NLMSG_LENGTH(sizeof(req)))
		return;

	memcpy(&req, nlmsg_data(nlh), sizeof(req));
	if (req.magic != NFK_GYRO_MAGIC)
		return;
	if (req.cmd < NFK_GYRO_CMD_SET || req.cmd > NFK_GYRO_CMD_REMOVE)
		return;

	/* Control is root-only; the caller cannot make another app do this. */
	if (!uid_eq(NETLINK_CB(skb).creds.uid, GLOBAL_ROOT_UID))
		return;

	spin_lock_irqsave(&g_nfk_gyro_lock, flags);
	if (!READ_ONCE(g_nfk_gyro_exiting)) {
		g_nfk_gyro_pending = req;
		g_nfk_gyro_pending_valid = true;
	}
	spin_unlock_irqrestore(&g_nfk_gyro_lock, flags);
	schedule_work(&g_nfk_gyro_work);
}

int nfk_gyro_init(void)
{
	struct netlink_kernel_cfg cfg = {
		.input = nfk_gyro_nl_input,
	};

	spin_lock_init(&g_nfk_gyro_lock);
	INIT_WORK(&g_nfk_gyro_work, nfk_gyro_work_fn);
	g_nfk_gyro_nl = netlink_kernel_create(&init_net, NFK_GYRO_NL_PROTO, &cfg);
	if (!g_nfk_gyro_nl)
		return -ENODEV;
	g_nfk_gyro_ready = true;
	return 0;
}

void nfk_gyro_exit(void)
{
	unsigned long flags;

	if (!g_nfk_gyro_ready)
		return;
	spin_lock_irqsave(&g_nfk_gyro_lock, flags);
	WRITE_ONCE(g_nfk_gyro_exiting, true);
	g_nfk_gyro_pending_valid = false;
	spin_unlock_irqrestore(&g_nfk_gyro_lock, flags);

	cancel_work_sync(&g_nfk_gyro_work);
	gyro_sock_shutdown();
	gyro_sock_remove();

	if (g_nfk_gyro_nl) {
		netlink_kernel_release(g_nfk_gyro_nl);
		g_nfk_gyro_nl = NULL;
	}
}
