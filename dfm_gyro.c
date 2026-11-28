/*
 * dfm private gyro injection.
 *
 * This is an dfm-only feature. It deliberately does not touch the
 * enenkernel 'D' ioctl ABI; control uses a private 'D' ioctl on the already
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

#include "dfm_gyro.h"
#include "compat.h"

#define DFM_GYRO_EVENT_SIZE	0x68u
#define DFM_GYRO_TYPE_HAL	0x08u
#define DFM_GYRO_DATA_OFF	0x18u
#define DFM_GYRO_TYPE_CAL	4
#define DFM_GYRO_TYPE_UNCAL	16
#define DFM_GYRO_IOV_MAX	16u
#define DFM_GYRO_MAXACTIVE	256

/* nofault helpers are not exported by all GKI kernels; resolve via compat. */
static long dfm_gyro_copy_from_user(void *dst, const void __user *src,
				    size_t size)
{
	if (!dfm_copy_from_user_nofault)
		return -EOPNOTSUPP;
	return dfm_copy_from_user_nofault(dst, src, size);
}

static long dfm_gyro_copy_to_user(void __user *dst, const void *src,
				  size_t size)
{
	if (!dfm_copy_to_user_nofault)
		return -EOPNOTSUPP;
	return dfm_copy_to_user_nofault(dst, src, size);
}

/* TEMPORARY diagnostic logging: set to 0 (and rebuild) to restore silence. */
#define DFM_GYRO_DIAG_LOG	0

struct dfm_gyro_ctx {
	bool flat;
	void __user *buf;
	unsigned long len;
	struct iovec __user *iov;
	unsigned int iovlen;
};

static struct mutex dfm_gyro_lock;
static bool dfm_gyro_registered;
static bool dfm_gyro_enabled;
static pid_t dfm_gyro_tgid;
static u32 dfm_gyro_x_bits;
static u32 dfm_gyro_y_bits;
static atomic64_t dfm_gyro_processed = ATOMIC64_INIT(0);
static atomic64_t dfm_gyro_rewritten = ATOMIC64_INIT(0);

static struct kretprobe dfm_gyro_probes[3];

static int dfm_gyro_entry_0(struct kretprobe_instance *ri, struct pt_regs *regs);
static int dfm_gyro_entry_1(struct kretprobe_instance *ri, struct pt_regs *regs);
static int dfm_gyro_entry_2(struct kretprobe_instance *ri, struct pt_regs *regs);

struct dfm_gyro_candidate {
	const char *name;
	bool flat;
	kretprobe_handler_t entry;
};

static const struct dfm_gyro_candidate dfm_gyro_candidates[] = {
	{ "__arm64_sys_recvmsg",  false, dfm_gyro_entry_0 },
	{ "__arm64_sys_recvfrom", true,  dfm_gyro_entry_1 },
	{ "__arm64_sys_read",     true,  dfm_gyro_entry_2 },
};

static bool dfm_gyro_probe_live[ARRAY_SIZE(dfm_gyro_candidates)];

static int dfm_gyro_read32(struct iovec *iov, unsigned int n,
			   unsigned long off, u32 *out)
{
	unsigned int i;
	unsigned long base = 0;
	u32 val;

	for (i = 0; i < n; i++) {
		unsigned long len = iov[i].iov_len;

		if (len > ULONG_MAX - base)
			return -EFAULT;
		if (off < base + len) {
			if (dfm_gyro_copy_from_user(&val,
					(u32 __user *)((char __user *)iov[i].iov_base +
						       (off - base)), sizeof(val)))
				return -EFAULT;
			*out = val;
			return 0;
		}
		base += len;
	}
	return -EFAULT;
}

static int dfm_gyro_write32(struct iovec *iov, unsigned int n,
			    unsigned long off, u32 val)
{
	unsigned int i;
	unsigned long base = 0;

	for (i = 0; i < n; i++) {
		unsigned long len = iov[i].iov_len;

		if (len > ULONG_MAX - base)
			return -EFAULT;
		if (off < base + len)
			return dfm_gyro_copy_to_user(
				(u32 __user *)((char __user *)iov[i].iov_base +
					       (off - base)), &val, sizeof(val));
		base += len;
	}
	return -EFAULT;
}

static void dfm_gyro_rewrite(struct iovec *iov, unsigned int n,
			     unsigned long total)
{
	unsigned long off;

	for (off = 0; off + DFM_GYRO_EVENT_SIZE <= total;
	     off += DFM_GYRO_EVENT_SIZE) {
		u32 type = 0, x, y;
		bool found = false;

		/* 只认 HAL ASensorEvent 的 type@+0x08。不要用 +0x04 的
		 * NDK 猜测回退：HAL 的 sensor id 也可能是 4/16，会把
		 * 加速度计/磁力计误判成陀螺仪，产生改写副作用。
		 */
		if (!dfm_gyro_read32(iov, n, off + DFM_GYRO_TYPE_HAL, &type) &&
		    (type == DFM_GYRO_TYPE_CAL || type == DFM_GYRO_TYPE_UNCAL))
			found = true;
		if (!found)
			continue;

		atomic64_inc(&dfm_gyro_processed);
		if (dfm_gyro_read32(iov, n, off + DFM_GYRO_DATA_OFF, &x))
			continue;
		if (dfm_gyro_read32(iov, n, off + DFM_GYRO_DATA_OFF + 4, &y))
			continue;

		x = READ_ONCE(dfm_gyro_x_bits);
		y = READ_ONCE(dfm_gyro_y_bits);
		if (dfm_gyro_write32(iov, n, off + DFM_GYRO_DATA_OFF, x))
			continue;
		if (dfm_gyro_write32(iov, n, off + DFM_GYRO_DATA_OFF + 4, y))
			continue;
		{
			u64 n = (u64)atomic64_inc_return(&dfm_gyro_rewritten);

			if (DFM_GYRO_DIAG_LOG &&
			    (n == 1 || (n & 1023) == 0))
				pr_info("dfm_gyro: rewrite n=%llu tgid=%d type=%u off=%lu\n",
					n, current->tgid, type, off);
		}
	}
}

/*
 * __arm64_sys_* entry takes a struct pt_regs * in x0. The real syscall
 * arguments live in the pointed-to user register frame.
 */
static int dfm_gyro_entry(struct kretprobe_instance *ri, struct pt_regs *regs,
			  unsigned int idx)
{
	struct dfm_gyro_ctx *ctx = (struct dfm_gyro_ctx *)ri->data;
	struct pt_regs *ur;
	struct user_msghdr umh;

	memset(ctx, 0, sizeof(*ctx));
	if (!READ_ONCE(dfm_gyro_enabled) || !READ_ONCE(dfm_gyro_registered))
		return 1;

	if (READ_ONCE(dfm_gyro_tgid) > 0 &&
	    current->tgid != READ_ONCE(dfm_gyro_tgid))
		return 1;

	ur = (struct pt_regs *)regs->regs[0];
	if (!ur || !user_mode(ur))
		return 1;

	if (dfm_gyro_candidates[idx].flat) {
		ctx->flat = true;
		ctx->buf = (void __user *)ur->regs[1];
		ctx->len = (unsigned long)ur->regs[2];
		if (!ctx->buf || ctx->len < DFM_GYRO_EVENT_SIZE)
			return 1;
		if (ctx->len % DFM_GYRO_EVENT_SIZE)
			return 1;
		return 0;
	}

	if (dfm_gyro_copy_from_user(&umh, (void __user *)ur->regs[1], sizeof(umh)))
		return 1;
	if (!umh.msg_iov || !umh.msg_iovlen || umh.msg_iovlen > DFM_GYRO_IOV_MAX)
		return 1;

	ctx->flat = false;
	ctx->iov = umh.msg_iov;
	ctx->iovlen = (unsigned int)umh.msg_iovlen;
	return 0;
}

static int dfm_gyro_entry_0(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return dfm_gyro_entry(ri, regs, 0);
}

static int dfm_gyro_entry_1(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return dfm_gyro_entry(ri, regs, 1);
}

static int dfm_gyro_entry_2(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return dfm_gyro_entry(ri, regs, 2);
}

static int dfm_gyro_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct dfm_gyro_ctx *ctx = (struct dfm_gyro_ctx *)ri->data;
	struct iovec iov[DFM_GYRO_IOV_MAX];
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
		dfm_gyro_rewrite(&one, 1, total);
		return 0;
	}

	if (!ctx->iovlen || ctx->iovlen > DFM_GYRO_IOV_MAX)
		return 0;
	if (dfm_gyro_copy_from_user(iov, ctx->iov,
				   ctx->iovlen * sizeof(struct iovec)))
		return 0;

	dfm_gyro_rewrite(iov, ctx->iovlen, total);
	return 0;
}

static void dfm_gyro_unregister_locked(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(dfm_gyro_probes); i++) {
		if (dfm_gyro_probe_live[i]) {
			unregister_kretprobe(&dfm_gyro_probes[i]);
			dfm_gyro_probe_live[i] = false;
		}
	}
	WRITE_ONCE(dfm_gyro_registered, false);
}

static int dfm_gyro_register_locked(void)
{
	unsigned int i;
	unsigned int live = 0;
	int ret;

	if (READ_ONCE(dfm_gyro_registered))
		return 0;

	for (i = 0; i < ARRAY_SIZE(dfm_gyro_candidates); i++) {
		struct kretprobe *probe = &dfm_gyro_probes[i];

		dfm_gyro_probe_live[i] = false;
		memset(probe, 0, sizeof(*probe));
		probe->kp.symbol_name = dfm_gyro_candidates[i].name;
		probe->entry_handler = dfm_gyro_candidates[i].entry;
		probe->handler = dfm_gyro_ret;
		probe->maxactive = DFM_GYRO_MAXACTIVE;
		probe->data_size = sizeof(struct dfm_gyro_ctx);

		ret = register_kretprobe(probe);
		if (ret)
			continue;
		dfm_gyro_probe_live[i] = true;
		live++;
	}

	if (!live) {
		if (DFM_GYRO_DIAG_LOG)
			pr_warn("dfm_gyro: no kretprobe registered (syscall symbols unavailable)\n");
		return -ENOENT;
	}
	WRITE_ONCE(dfm_gyro_registered, true);
	if (DFM_GYRO_DIAG_LOG) {
		unsigned int j;

		for (j = 0; j < ARRAY_SIZE(dfm_gyro_probes); j++) {
			if (dfm_gyro_probe_live[j])
				pr_info("dfm_gyro: probe[%u] %s live\n",
					j, dfm_gyro_candidates[j].name);
		}
	}
	return 0;
}

int dfm_gyro_init(void)
{
	mutex_init(&dfm_gyro_lock);
	if (DFM_GYRO_DIAG_LOG)
		pr_info("dfm_gyro: init, diagnostic log enabled\n");
	dfm_gyro_registered = false;
	dfm_gyro_enabled = false;
	dfm_gyro_tgid = 0;
	memset(dfm_gyro_probe_live, 0, sizeof(dfm_gyro_probe_live));
	return 0;
}

void dfm_gyro_exit(void)
{
	mutex_lock(&dfm_gyro_lock);
	WRITE_ONCE(dfm_gyro_enabled, false);
	dfm_gyro_unregister_locked();
	mutex_unlock(&dfm_gyro_lock);
	mutex_destroy(&dfm_gyro_lock);
	if (DFM_GYRO_DIAG_LOG)
		pr_info("dfm_gyro: exit\n");
}

long dfm_gyro_ioctl(void __user *arg)
{
	struct dfm_gyro_req req;
	long ret = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&req, arg, sizeof(req)))
		return -EFAULT;
	if (req.abi_version != DFM_GYRO_ABI_VERSION)
		return -EPROTO;

	mutex_lock(&dfm_gyro_lock);
	switch (req.cmd) {
	case DFM_GYRO_CMD_SET:
		if (req.pid <= 0) {
			ret = -EINVAL;
			break;
		}
		WRITE_ONCE(dfm_gyro_tgid, req.pid);
		WRITE_ONCE(dfm_gyro_x_bits, req.x_bits);
		WRITE_ONCE(dfm_gyro_y_bits, req.y_bits);
		WRITE_ONCE(dfm_gyro_enabled, true);
		ret = dfm_gyro_register_locked();
		if (ret)
			WRITE_ONCE(dfm_gyro_enabled, false);
		if (DFM_GYRO_DIAG_LOG)
			pr_info("dfm_gyro: set pid=%d active=%d ret=%ld\n", req.pid, READ_ONCE(dfm_gyro_registered), ret);
		break;
	case DFM_GYRO_CMD_ENABLE:
		if (READ_ONCE(dfm_gyro_tgid) <= 0) {
			ret = -EINVAL;
			break;
		}
		WRITE_ONCE(dfm_gyro_enabled, true);
		ret = dfm_gyro_register_locked();
		if (ret)
			WRITE_ONCE(dfm_gyro_enabled, false);
		if (DFM_GYRO_DIAG_LOG)
			pr_info("dfm_gyro: enable pid=%d active=%d ret=%ld\n", READ_ONCE(dfm_gyro_tgid), READ_ONCE(dfm_gyro_registered), ret);
		break;
	case DFM_GYRO_CMD_DISABLE:
		WRITE_ONCE(dfm_gyro_enabled, false);
		if (DFM_GYRO_DIAG_LOG)
			pr_info("dfm_gyro: disable\n");
		break;
	case DFM_GYRO_CMD_REMOVE:
		WRITE_ONCE(dfm_gyro_enabled, false);
		dfm_gyro_unregister_locked();
		WRITE_ONCE(dfm_gyro_tgid, 0);
		if (DFM_GYRO_DIAG_LOG)
			pr_info("dfm_gyro: remove\n");
		break;
	case DFM_GYRO_CMD_QUERY:
		break;
	default:
		ret = -EINVAL;
		break;
	}

	req.enable = READ_ONCE(dfm_gyro_enabled);
	req.active = READ_ONCE(dfm_gyro_registered);
	req.pid = READ_ONCE(dfm_gyro_tgid);
	req.processed = (u32)atomic64_read(&dfm_gyro_processed);
	req.rewritten = (u32)atomic64_read(&dfm_gyro_rewritten);
	mutex_unlock(&dfm_gyro_lock);

	if (ret)
		return ret;
	if (copy_to_user(arg, &req, sizeof(req)))
		return -EFAULT;
	return 0;
}
