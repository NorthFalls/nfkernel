/*
 * nfkernel private gyro injection.
 *
 * This is an nfkernel-only feature. It deliberately does not touch the
 * enenkernel 'D' ioctl ABI; control uses a private 'N' ioctl on the already
 * installed driver fd. The sensor rewrite is installed lazily on first use so
 * module load stays as small as the known-good build.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
#include <linux/socket.h>
#include <linux/mutex.h>
#include <linux/atomic.h>
#include <linux/capability.h>
#include <linux/version.h>
#include <asm/ptrace.h>

#include "nfk_gyro.h"

#define NFK_GYRO_EVENT_SIZE	0x68u
#define NFK_GYRO_TYPE_HAL	0x08u
#define NFK_GYRO_TYPE_NDK	0x04u
#define NFK_GYRO_DATA_OFF	0x18u
#define NFK_GYRO_TYPE_CAL	4
#define NFK_GYRO_TYPE_UNCAL	16
#define NFK_GYRO_IOV_MAX	16u
#define NFK_GYRO_MAXACTIVE	256

struct nfk_gyro_ctx {
	bool flat;
	void __user *buf;
	unsigned long len;
	struct iovec __user *iov;
	unsigned int iovlen;
};

static struct mutex nfk_gyro_lock;
static bool nfk_gyro_registered;
static bool nfk_gyro_enabled;
static pid_t nfk_gyro_tgid;
static u32 nfk_gyro_x_bits;
static u32 nfk_gyro_y_bits;
static atomic64_t nfk_gyro_processed = ATOMIC64_INIT(0);
static atomic64_t nfk_gyro_rewritten = ATOMIC64_INIT(0);

static struct kretprobe nfk_gyro_probes[3];
static unsigned int nfk_gyro_probe_count;

static int nfk_gyro_entry_0(struct kretprobe_instance *ri, struct pt_regs *regs);
static int nfk_gyro_entry_1(struct kretprobe_instance *ri, struct pt_regs *regs);
static int nfk_gyro_entry_2(struct kretprobe_instance *ri, struct pt_regs *regs);

struct nfk_gyro_candidate {
	const char *name;
	bool flat;
	kretprobe_handler_t entry;
};

static const struct nfk_gyro_candidate nfk_gyro_candidates[] = {
	{ "__arm64_sys_recvmsg",  false, nfk_gyro_entry_0 },
	{ "__arm64_sys_recvfrom", true,  nfk_gyro_entry_1 },
	{ "__arm64_sys_read",     true,  nfk_gyro_entry_2 },
};

static int nfk_gyro_read32(struct iovec *iov, unsigned int n,
			   unsigned long off, u32 *out)
{
	unsigned int i;
	unsigned long base = 0;

	for (i = 0; i < n; i++) {
		unsigned long len = iov[i].iov_len;

		if (off < base + len)
			return get_user(*out,
					(u32 __user *)((char __user *)iov[i].iov_base +
						       (off - base)));
		base += len;
	}
	return -EFAULT;
}

static int nfk_gyro_write32(struct iovec *iov, unsigned int n,
			    unsigned long off, u32 val)
{
	unsigned int i;
	unsigned long base = 0;

	for (i = 0; i < n; i++) {
		unsigned long len = iov[i].iov_len;

		if (off < base + len)
			return put_user(val,
					(u32 __user *)((char __user *)iov[i].iov_base +
						       (off - base)));
		base += len;
	}
	return -EFAULT;
}

static void nfk_gyro_rewrite(struct iovec *iov, unsigned int n,
			     unsigned long total)
{
	unsigned long off;

	for (off = 0; off + NFK_GYRO_EVENT_SIZE <= total;
	     off += NFK_GYRO_EVENT_SIZE) {
		u32 type, x, y;

		if (nfk_gyro_read32(iov, n, off + NFK_GYRO_TYPE_HAL, &type)) {
			if (nfk_gyro_read32(iov, n, off + NFK_GYRO_TYPE_NDK, &type))
				continue;
		}
		if (type != NFK_GYRO_TYPE_CAL && type != NFK_GYRO_TYPE_UNCAL)
			continue;

		atomic64_inc(&nfk_gyro_processed);
		if (nfk_gyro_read32(iov, n, off + NFK_GYRO_DATA_OFF, &x))
			continue;
		if (nfk_gyro_read32(iov, n, off + NFK_GYRO_DATA_OFF + 4, &y))
			continue;

		x = READ_ONCE(nfk_gyro_x_bits);
		y = READ_ONCE(nfk_gyro_y_bits);
		if (nfk_gyro_write32(iov, n, off + NFK_GYRO_DATA_OFF, x))
			continue;
		if (nfk_gyro_write32(iov, n, off + NFK_GYRO_DATA_OFF + 4, y))
			continue;
		atomic64_inc(&nfk_gyro_rewritten);
	}
}

/*
 * __arm64_sys_* entry takes a struct pt_regs * in x0. The real syscall
 * arguments live in the pointed-to user register frame.
 */
static int nfk_gyro_entry(struct kretprobe_instance *ri, struct pt_regs *regs,
			  unsigned int idx)
{
	struct nfk_gyro_ctx *ctx = (struct nfk_gyro_ctx *)ri->data;
	struct pt_regs *ur;
	struct user_msghdr umh;

	memset(ctx, 0, sizeof(*ctx));
	if (!READ_ONCE(nfk_gyro_enabled) || !READ_ONCE(nfk_gyro_registered))
		return 1;

	if (READ_ONCE(nfk_gyro_tgid) > 0 &&
	    current->tgid != READ_ONCE(nfk_gyro_tgid))
		return 1;

	ur = (struct pt_regs *)regs->regs[0];
	if (!ur || !user_mode(ur))
		return 1;

	if (nfk_gyro_candidates[idx].flat) {
		ctx->flat = true;
		ctx->buf = (void __user *)ur->regs[1];
		ctx->len = (unsigned long)ur->regs[2];
		if (!ctx->buf || ctx->len < NFK_GYRO_EVENT_SIZE)
			return 1;
		if (ctx->len % NFK_GYRO_EVENT_SIZE)
			return 1;
		return 0;
	}

	if (copy_from_user(&umh, (void __user *)ur->regs[1], sizeof(umh)))
		return 1;
	if (!umh.msg_iov || !umh.msg_iovlen || umh.msg_iovlen > NFK_GYRO_IOV_MAX)
		return 1;

	ctx->flat = false;
	ctx->iov = umh.msg_iov;
	ctx->iovlen = (unsigned int)umh.msg_iovlen;
	return 0;
}

static int nfk_gyro_entry_0(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return nfk_gyro_entry(ri, regs, 0);
}

static int nfk_gyro_entry_1(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return nfk_gyro_entry(ri, regs, 1);
}

static int nfk_gyro_entry_2(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return nfk_gyro_entry(ri, regs, 2);
}

static int nfk_gyro_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct nfk_gyro_ctx *ctx = (struct nfk_gyro_ctx *)ri->data;
	struct iovec iov[NFK_GYRO_IOV_MAX];
	unsigned long total;
	long ret;

	if (!ctx->flat && !ctx->iov)
		return 0;

	ret = (long)regs_return_value(regs);
	if (ret <= 0)
		return 0;
	total = (unsigned long)ret;

	if (ctx->flat) {
		struct iovec one;

		if (total > ctx->len)
			return 0;
		one.iov_base = ctx->buf;
		one.iov_len = total;
		nfk_gyro_rewrite(&one, 1, total);
		return 0;
	}

	if (!ctx->iovlen || ctx->iovlen > NFK_GYRO_IOV_MAX)
		return 0;
	if (copy_from_user(iov, ctx->iov,
			   ctx->iovlen * sizeof(struct iovec)))
		return 0;

	nfk_gyro_rewrite(iov, ctx->iovlen, total);
	return 0;
}

static void nfk_gyro_unregister_locked(void)
{
	unsigned int i;

	for (i = 0; i < nfk_gyro_probe_count; i++)
		unregister_kretprobe(&nfk_gyro_probes[i]);
	nfk_gyro_probe_count = 0;
	WRITE_ONCE(nfk_gyro_registered, false);
}

static int nfk_gyro_register_locked(void)
{
	unsigned int i;
	int ret;

	if (READ_ONCE(nfk_gyro_registered))
		return 0;

	for (i = 0; i < ARRAY_SIZE(nfk_gyro_candidates); i++) {
		struct kretprobe *probe = &nfk_gyro_probes[i];

		memset(probe, 0, sizeof(*probe));
		probe->kp.symbol_name = nfk_gyro_candidates[i].name;
		probe->entry_handler = nfk_gyro_candidates[i].entry;
		probe->handler = nfk_gyro_ret;
		probe->maxactive = NFK_GYRO_MAXACTIVE;
		probe->data_size = sizeof(struct nfk_gyro_ctx);

		ret = register_kretprobe(probe);
		if (ret) {
			pr_debug("nfk_gyro: %s unavailable: %d\n",
				 nfk_gyro_candidates[i].name, ret);
			continue;
		}
		nfk_gyro_probe_count++;
	}

	if (!nfk_gyro_probe_count)
		return -ENOENT;
	WRITE_ONCE(nfk_gyro_registered, true);
	return 0;
}

int nfk_gyro_init(void)
{
	mutex_init(&nfk_gyro_lock);
	nfk_gyro_registered = false;
	nfk_gyro_enabled = false;
	nfk_gyro_tgid = 0;
	nfk_gyro_probe_count = 0;
	return 0;
}

void nfk_gyro_exit(void)
{
	mutex_lock(&nfk_gyro_lock);
	WRITE_ONCE(nfk_gyro_enabled, false);
	nfk_gyro_unregister_locked();
	mutex_unlock(&nfk_gyro_lock);
	mutex_destroy(&nfk_gyro_lock);
}

long nfk_gyro_ioctl(void __user *arg)
{
	struct nfk_gyro_req req;
	long ret = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&req, arg, sizeof(req)))
		return -EFAULT;
	if (req.abi_version != NFK_GYRO_ABI_VERSION)
		return -EPROTO;

	mutex_lock(&nfk_gyro_lock);
	switch (req.cmd) {
	case NFK_GYRO_CMD_SET:
		if (req.pid <= 0) {
			ret = -EINVAL;
			break;
		}
		WRITE_ONCE(nfk_gyro_tgid, req.pid);
		WRITE_ONCE(nfk_gyro_x_bits, req.x_bits);
		WRITE_ONCE(nfk_gyro_y_bits, req.y_bits);
		WRITE_ONCE(nfk_gyro_enabled, true);
		ret = nfk_gyro_register_locked();
		if (ret)
			WRITE_ONCE(nfk_gyro_enabled, false);
		break;
	case NFK_GYRO_CMD_ENABLE:
		WRITE_ONCE(nfk_gyro_enabled, true);
		ret = nfk_gyro_register_locked();
		if (ret)
			WRITE_ONCE(nfk_gyro_enabled, false);
		break;
	case NFK_GYRO_CMD_DISABLE:
		WRITE_ONCE(nfk_gyro_enabled, false);
		break;
	case NFK_GYRO_CMD_REMOVE:
		WRITE_ONCE(nfk_gyro_enabled, false);
		nfk_gyro_unregister_locked();
		WRITE_ONCE(nfk_gyro_tgid, 0);
		break;
	case NFK_GYRO_CMD_QUERY:
		break;
	default:
		ret = -EINVAL;
		break;
	}

	req.enable = READ_ONCE(nfk_gyro_enabled);
	req.active = READ_ONCE(nfk_gyro_registered);
	req.pid = READ_ONCE(nfk_gyro_tgid);
	req.processed = (u32)atomic64_read(&nfk_gyro_processed);
	req.rewritten = (u32)atomic64_read(&nfk_gyro_rewritten);
	mutex_unlock(&nfk_gyro_lock);

	if (ret)
		return ret;
	if (copy_to_user(arg, &req, sizeof(req)))
		return -EFAULT;
	return 0;
}
