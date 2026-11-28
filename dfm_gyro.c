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
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/jiffies.h>
#include <linux/string.h>
#include <linux/path.h>
#include <linux/dcache.h>
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
static atomic64_t dfm_gyro_entries = ATOMIC64_INIT(0);
static u32 dfm_gyro_samples[8][3];
static u32 dfm_gyro_sample_count;

/*
 * Delta Force and several Tencent FPS builds use SensorDirectChannel: the HAL
 * writes sensors_event_t records straight into an ashmem mapping of the game
 * process, bypassing read/recvmsg.  The kretprobe path above cannot see that
 * traffic.  Direct mode finds the ashmem queue and rewrites +0x18/+0x1c in
 * every gyroscope record.  It only starts when the private D48 ioctl enables
 * it, so module load is unaffected.
 */
#define DFM_GYRO_DIRECT_MAX_RANGES	32
#define DFM_GYRO_DIRECT_MAX_BYTES	(256u * 1024u)
#define DFM_GYRO_DIRECT_INTERVAL_MS	8

struct dfm_gyro_direct_range {
	unsigned long start;
	unsigned long len;
	bool writable;
};

static struct task_struct *dfm_gyro_direct_task;
static unsigned long dfm_gyro_direct_base;
static unsigned long dfm_gyro_direct_len;
static void *dfm_gyro_direct_buf;
static bool dfm_gyro_direct_active;
static struct delayed_work dfm_gyro_direct_work;
static atomic64_t dfm_gyro_direct_writes = ATOMIC64_INIT(0);
static atomic64_t dfm_gyro_direct_events = ATOMIC64_INIT(0);
static unsigned int dfm_gyro_direct_fail_streak;
static unsigned int dfm_gyro_direct_idle_scans;
static u64 dfm_gyro_direct_last_ts;

static void dfm_gyro_direct_work_fn(struct work_struct *work);

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

static bool dfm_gyro_direct_path(struct vm_area_struct *vma)
{
	const char *name;

	if (!vma->vm_file)
		return false;
	name = vma->vm_file->f_path.dentry->d_name.name;
	if (!name)
		return false;
	return strstr(name, "ashmem") || strstr(name, "memfd") ||
	       strstr(name, "dmabuf") || strstr(name, "gralloc") ||
	       strstr(name, "dma_heap");
}

static struct task_struct *dfm_gyro_direct_get_task(pid_t tgid)
{
	struct task_struct *task;
	struct pid *pid;

	rcu_read_lock();
	pid = find_vpid(tgid);
	task = pid ? pid_task(pid, PIDTYPE_PID) : NULL;
	if (task)
		get_task_struct(task);
	rcu_read_unlock();
	return task;
}

static bool dfm_gyro_range_has_event(struct task_struct *task,
				     unsigned long start, unsigned long len)
{
	void *buf;
	unsigned long off;
	int n;
	bool found = false;

	if (!dfm_access_process_vm)
		return false;
	buf = kvmalloc(len, GFP_KERNEL);
	if (!buf)
		return false;
	n = dfm_access_process_vm(task, start, buf, (int)len, 0);
	if (n >= (int)DFM_GYRO_EVENT_SIZE) {
		for (off = 0; off + DFM_GYRO_EVENT_SIZE <= (unsigned long)n;
		     off += DFM_GYRO_EVENT_SIZE) {
			u32 version, sensor, type;
			u64 timestamp;

			memcpy(&version, (char *)buf + off + 0x00, sizeof(version));
			memcpy(&sensor, (char *)buf + off + 0x04, sizeof(sensor));
			memcpy(&type, (char *)buf + off + 0x08, sizeof(type));
			memcpy(&timestamp, (char *)buf + off + 0x10,
			       sizeof(timestamp));
			if (version == 1 && sensor && timestamp &&
			    (type == DFM_GYRO_TYPE_CAL ||
			     type == DFM_GYRO_TYPE_UNCAL)) {
				found = true;
				break;
			}
		}
	}
	kvfree(buf);
	return found;
}

/* Find one ashmem/memfd mapping in the target that is large enough to hold a
 * sensor event queue.  Prefer a mapping that already contains a gyro event. */
static int dfm_gyro_direct_find_range(struct task_struct *task,
				      unsigned long *start,
				      unsigned long *len)
{
	struct dfm_gyro_direct_range ranges[DFM_GYRO_DIRECT_MAX_RANGES];
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	unsigned int nr = 0;
	unsigned int i;
	unsigned long bytes;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	struct vma_iterator vmi;
#endif

	mm = get_task_mm(task);
	if (!mm)
		return -ESRCH;
	mmap_read_lock(mm);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	vma_iter_init(&vmi, mm, 0);
	for_each_vma(vmi, vma) {
		if (nr >= ARRAY_SIZE(ranges))
			break;
#else
	for (vma = mm->mmap; vma && nr < ARRAY_SIZE(ranges); vma = vma->vm_next) {
#endif
		/* The app may map the direct report read-only; HAL owns the
		 * writable side.  Include read-only shared mappings and use
		 * FOLL_FORCE for the rewrite. */
		if (!(vma->vm_flags & VM_SHARED) || !(vma->vm_flags & VM_READ))
			continue;
		if (!dfm_gyro_direct_path(vma))
			continue;
		bytes = vma->vm_end - vma->vm_start;
		if (bytes < DFM_GYRO_EVENT_SIZE)
			continue;
		if (bytes > DFM_GYRO_DIRECT_MAX_BYTES)
			bytes = DFM_GYRO_DIRECT_MAX_BYTES;
		ranges[nr].start = vma->vm_start;
		ranges[nr].len = bytes;
		ranges[nr].writable = !!(vma->vm_flags & VM_WRITE);
		nr++;
	}
	mmap_read_unlock(mm);
	mmput(mm);

	for (i = 0; i < nr; i++) {
		/* Prefer a writable mapping of the same queue if the app keeps
		 * both a read-only consumer view and a writable view. */
		if (!ranges[i].writable)
			continue;
		if (dfm_gyro_range_has_event(task, ranges[i].start,
					     ranges[i].len)) {
			*start = ranges[i].start;
			*len = ranges[i].len;
			return 0;
		}
	}
	for (i = 0; i < nr; i++) {
		if (dfm_gyro_range_has_event(task, ranges[i].start,
					     ranges[i].len)) {
			*start = ranges[i].start;
			*len = ranges[i].len;
			return 0;
		}
	}
	/* No gyro event yet: the game may still be creating the direct
	 * channel.  Attach to one candidate mapping and let the worker look
	 * for a real gyro record; the worker only writes records that pass
	 * the full version/sensor/type/timestamp check, and gives up after a
	 * short idle period if this is just an unrelated ashmem buffer. */
	if (nr) {
		for (i = 0; i < nr; i++) {
			if (ranges[i].writable) {
				*start = ranges[i].start;
				*len = ranges[i].len;
				return 0;
			}
		}
		*start = ranges[0].start;
		*len = ranges[0].len;
		return 0;
	}
	return -ENOENT;
}

/* Read the target queue, rewrite every gyroscope event's x/y.  Runs from a
 * workqueue, so access_process_vm() may sleep. */
static int dfm_gyro_direct_scan_range(struct task_struct *task,
				      unsigned long start, unsigned long len,
				      void *buf, int *events)
{
	int n;
	unsigned long off;
	u64 newest = 0;

	n = dfm_access_process_vm(task, start, buf, (int)len, 0);
	if (n < (int)DFM_GYRO_EVENT_SIZE)
		return -EFAULT;

	for (off = 0; off + DFM_GYRO_EVENT_SIZE <= (unsigned long)n; off += DFM_GYRO_EVENT_SIZE) {
		u32 version, sensor, type;
		u64 timestamp, xy;

		memcpy(&version, (char *)buf + off + 0x00, sizeof(version));
		memcpy(&sensor, (char *)buf + off + 0x04, sizeof(sensor));
		memcpy(&type, (char *)buf + off + 0x08, sizeof(type));
		memcpy(&timestamp, (char *)buf + off + 0x10, sizeof(timestamp));
		if (version != 1 || !sensor || !timestamp)
			continue;
		if (type != DFM_GYRO_TYPE_CAL && type != DFM_GYRO_TYPE_UNCAL)
			continue;
		/* The queue is a ring: old events stay in the buffer.  Only
		 * rewrite events newer than the last one seen, otherwise we
		 * burn power on stale records and never enter the idle cadence. */
		if (timestamp <= READ_ONCE(dfm_gyro_direct_last_ts))
			continue;
		if (timestamp > newest)
			newest = timestamp;

		atomic64_inc(&dfm_gyro_direct_events);
		(*events)++;
		xy = ((u64)READ_ONCE(dfm_gyro_y_bits) << 32) |
		     (u64)READ_ONCE(dfm_gyro_x_bits);
		if (dfm_access_process_vm(task, start + off + DFM_GYRO_DATA_OFF,
					  &xy, sizeof(xy),
					  FOLL_WRITE | FOLL_FORCE) == (int)sizeof(xy))
			atomic64_inc(&dfm_gyro_direct_writes);
	}
	if (newest > READ_ONCE(dfm_gyro_direct_last_ts))
		WRITE_ONCE(dfm_gyro_direct_last_ts, newest);
	return 0;
}

static void dfm_gyro_direct_work_fn(struct work_struct *work)
{
	void *buf = (void *)READ_ONCE(dfm_gyro_direct_buf);
	int events = 0;

	if (!READ_ONCE(dfm_gyro_direct_active) ||
	    !READ_ONCE(dfm_gyro_enabled))
		return;
	if (buf && dfm_gyro_direct_task) {
		int ret;

		ret = dfm_gyro_direct_scan_range(dfm_gyro_direct_task,
						 dfm_gyro_direct_base,
						 dfm_gyro_direct_len,
						 buf, &events);
		if (ret) {
			if (++dfm_gyro_direct_fail_streak >= 64)
				WRITE_ONCE(dfm_gyro_direct_active, false);
		} else {
			dfm_gyro_direct_fail_streak = 0;
			if (events) {
				dfm_gyro_direct_idle_scans = 0;
			} else if (++dfm_gyro_direct_idle_scans >= 128) {
				/* Candidate mapping was unrelated; stop scanning. */
				WRITE_ONCE(dfm_gyro_direct_active, false);
			}
		}
	}
	if (READ_ONCE(dfm_gyro_direct_active))
		schedule_delayed_work(&dfm_gyro_direct_work,
				      msecs_to_jiffies(events ?
					DFM_GYRO_DIRECT_INTERVAL_MS : 100));
}

static void dfm_gyro_direct_stop(void)
{
	WRITE_ONCE(dfm_gyro_direct_active, false);
	cancel_delayed_work_sync(&dfm_gyro_direct_work);
	if (dfm_gyro_direct_task) {
		put_task_struct(dfm_gyro_direct_task);
		dfm_gyro_direct_task = NULL;
	}
	if (dfm_gyro_direct_buf) {
		kvfree(dfm_gyro_direct_buf);
		dfm_gyro_direct_buf = NULL;
	}
	dfm_gyro_direct_base = 0;
	dfm_gyro_direct_len = 0;
	dfm_gyro_direct_fail_streak = 0;
	dfm_gyro_direct_idle_scans = 0;
	dfm_gyro_direct_last_ts = 0;
}

static int dfm_gyro_direct_start(pid_t tgid)
{
	struct task_struct *task;
	unsigned long start = 0, len = 0;
	void *buf;
	int ret;

	if (!dfm_access_process_vm)
		return -EOPNOTSUPP;
	if (READ_ONCE(dfm_gyro_direct_active))
		return 0;
	/* A previous worker may have stopped itself after repeated failures;
	 * its task/buffer are still owned here until the next start/stop. */
	if (dfm_gyro_direct_task || dfm_gyro_direct_buf)
		dfm_gyro_direct_stop();

	task = dfm_gyro_direct_get_task(tgid);
	if (!task)
		return -ESRCH;

	ret = dfm_gyro_direct_find_range(task, &start, &len);
	if (ret) {
		put_task_struct(task);
		return ret;
	}

	buf = kvmalloc(len, GFP_KERNEL);
	if (!buf) {
		put_task_struct(task);
		return -ENOMEM;
	}

	dfm_gyro_direct_task = task;
	dfm_gyro_direct_base = start;
	dfm_gyro_direct_len = len;
	dfm_gyro_direct_buf = buf;
	dfm_gyro_direct_fail_streak = 0;
	dfm_gyro_direct_idle_scans = 0;
	dfm_gyro_direct_last_ts = 0;
	WRITE_ONCE(dfm_gyro_direct_active, true);
	schedule_delayed_work(&dfm_gyro_direct_work,
			      msecs_to_jiffies(DFM_GYRO_DIRECT_INTERVAL_MS));
	return 0;
}

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
		/* A 4-byte field must fit entirely inside one iovec segment;
		 * segments are not guaranteed to be contiguous in user memory. */
		if (len >= sizeof(val) && off >= base &&
		    off - base <= len - sizeof(val)) {
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

static int dfm_gyro_write64(struct iovec *iov, unsigned int n,
			    unsigned long off, u64 val)
{
	unsigned int i;
	unsigned long base = 0;

	for (i = 0; i < n; i++) {
		unsigned long len = iov[i].iov_len;

		if (len > ULONG_MAX - base)
			return -EFAULT;
		/* x/y must be one contiguous 8-byte field in a single segment;
		 * otherwise a two-step write could leave x modified if y faults. */
		if (len >= sizeof(val) && off >= base &&
		    off - base <= len - sizeof(val))
			return dfm_gyro_copy_to_user(
				(u64 __user *)((char __user *)iov[i].iov_base +
					       (off - base)), &val, sizeof(val));
		base += len;
	}
	return -EFAULT;
}

static void dfm_gyro_capture(struct iovec *iov, unsigned int n,
			     unsigned long total)
{
	u32 s[3];
	unsigned int slot;

	if (READ_ONCE(dfm_gyro_sample_count) >= ARRAY_SIZE(dfm_gyro_samples))
		return;
	/* Only sample buffers made of complete ASensorEvent records and
	 * reasonably sized; ordinary file/network reads are ignored. */
	if (total < DFM_GYRO_EVENT_SIZE || total % DFM_GYRO_EVENT_SIZE)
		return;
	if (total > DFM_GYRO_EVENT_SIZE * 64ul)
		return;
	if (dfm_gyro_read32(iov, n, 0, &s[0]) ||
	    dfm_gyro_read32(iov, n, 4, &s[1]) ||
	    dfm_gyro_read32(iov, n, 8, &s[2]))
		return;
	slot = READ_ONCE(dfm_gyro_sample_count);
	if (slot >= ARRAY_SIZE(dfm_gyro_samples))
		return;
	dfm_gyro_samples[slot][0] = s[0];
	dfm_gyro_samples[slot][1] = s[1];
	dfm_gyro_samples[slot][2] = s[2];
	WRITE_ONCE(dfm_gyro_sample_count, slot + 1);
}

static void dfm_gyro_rewrite(struct iovec *iov, unsigned int n,
			     unsigned long total)
{
	unsigned long off;

	for (off = 0; off + DFM_GYRO_EVENT_SIZE <= total;
	     off += DFM_GYRO_EVENT_SIZE) {
		u32 type = 0;
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
		/* Write x/y as one 64-bit pair so a fault cannot leave x half-updated. */
		if (dfm_gyro_write64(iov, n, off + DFM_GYRO_DATA_OFF,
				     ((u64)READ_ONCE(dfm_gyro_y_bits) << 32) |
				     (u64)READ_ONCE(dfm_gyro_x_bits)))
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

	atomic64_inc(&dfm_gyro_entries);

	if (dfm_gyro_candidates[idx].flat) {
		ctx->flat = true;
		ctx->buf = (void __user *)ur->regs[1];
		ctx->len = (unsigned long)ur->regs[2];
		if (!ctx->buf || ctx->len < DFM_GYRO_EVENT_SIZE)
			return 1;
		/* Do not require len to be an exact multiple: games may pass a
		 * larger read buffer; rewrite only complete events. */
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
	/* DISABLE may race an in-flight syscall; don't rewrite after disable. */
	if (!READ_ONCE(dfm_gyro_enabled))
		return 0;
	total = (unsigned long)ret;

	if (ctx->flat) {
		struct iovec one;

		if (total > ctx->len)
			return 0;
		one.iov_base = ctx->buf;
		one.iov_len = total;
		dfm_gyro_capture(&one, 1, total);
		dfm_gyro_rewrite(&one, 1, total);
		return 0;
	}

	if (!ctx->iovlen || ctx->iovlen > DFM_GYRO_IOV_MAX)
		return 0;
	if (dfm_gyro_copy_from_user(iov, ctx->iov,
				   ctx->iovlen * sizeof(struct iovec)))
		return 0;

	dfm_gyro_capture(iov, ctx->iovlen, total);
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
	INIT_DELAYED_WORK(&dfm_gyro_direct_work, dfm_gyro_direct_work_fn);
	dfm_gyro_direct_task = NULL;
	dfm_gyro_direct_buf = NULL;
	dfm_gyro_direct_base = 0;
	dfm_gyro_direct_len = 0;
	dfm_gyro_direct_fail_streak = 0;
	dfm_gyro_direct_idle_scans = 0;
	dfm_gyro_direct_last_ts = 0;
	WRITE_ONCE(dfm_gyro_direct_active, false);
	atomic64_set(&dfm_gyro_direct_events, 0);
	atomic64_set(&dfm_gyro_direct_writes, 0);
	if (DFM_GYRO_DIAG_LOG)
		pr_info("dfm_gyro: init, diagnostic log enabled\n");
	dfm_gyro_registered = false;
	dfm_gyro_enabled = false;
	dfm_gyro_tgid = 0;
	atomic64_set(&dfm_gyro_processed, 0);
	atomic64_set(&dfm_gyro_rewritten, 0);
	atomic64_set(&dfm_gyro_entries, 0);
	memset(dfm_gyro_probe_live, 0, sizeof(dfm_gyro_probe_live));
	memset(dfm_gyro_samples, 0, sizeof(dfm_gyro_samples));
	WRITE_ONCE(dfm_gyro_sample_count, 0);
	return 0;
}

void dfm_gyro_exit(void)
{
	mutex_lock(&dfm_gyro_lock);
	WRITE_ONCE(dfm_gyro_enabled, false);
	dfm_gyro_direct_stop();
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
	bool same_target = false;

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
		/* gyro_update() calls SET repeatedly with the same target.  Keep
		 * the existing probes/direct worker alive and only change x/y;
		 * otherwise every update would cancel and rescan the queue. */
		same_target = READ_ONCE(dfm_gyro_tgid) == req.pid &&
			      READ_ONCE(dfm_gyro_enabled) &&
			      READ_ONCE(dfm_gyro_registered);
		WRITE_ONCE(dfm_gyro_x_bits, req.x_bits);
		WRITE_ONCE(dfm_gyro_y_bits, req.y_bits);
		if (same_target) {
			if (!READ_ONCE(dfm_gyro_direct_active))
				(void)dfm_gyro_direct_start(req.pid);
			break;
		}
		dfm_gyro_direct_stop();
		WRITE_ONCE(dfm_gyro_tgid, req.pid);
		WRITE_ONCE(dfm_gyro_sample_count, 0);
		memset(dfm_gyro_samples, 0, sizeof(dfm_gyro_samples));
		WRITE_ONCE(dfm_gyro_enabled, true);
		ret = dfm_gyro_register_locked();
		if (ret)
			WRITE_ONCE(dfm_gyro_enabled, false);
		if (!ret)
			(void)dfm_gyro_direct_start(req.pid);
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
		if (!ret)
			(void)dfm_gyro_direct_start(READ_ONCE(dfm_gyro_tgid));
		if (DFM_GYRO_DIAG_LOG)
			pr_info("dfm_gyro: enable pid=%d active=%d ret=%ld\n", READ_ONCE(dfm_gyro_tgid), READ_ONCE(dfm_gyro_registered), ret);
		break;
	case DFM_GYRO_CMD_DISABLE:
		WRITE_ONCE(dfm_gyro_enabled, false);
		dfm_gyro_direct_stop();
		if (DFM_GYRO_DIAG_LOG)
			pr_info("dfm_gyro: disable\n");
		break;
	case DFM_GYRO_CMD_REMOVE:
		WRITE_ONCE(dfm_gyro_enabled, false);
		dfm_gyro_direct_stop();
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
	req.reserved[0] = 0;
	{
		unsigned int i;

		for (i = 0; i < ARRAY_SIZE(dfm_gyro_probes); i++)
			if (dfm_gyro_probe_live[i])
				req.reserved[0] |= 1u << i;
	}
	req.reserved[1] = (u32)atomic64_read(&dfm_gyro_entries);
	req.reserved[2] = (dfm_copy_from_user_nofault ? 1u : 0u) |
			  (dfm_copy_to_user_nofault ? 2u : 0u) |
			  (READ_ONCE(dfm_gyro_direct_active) ? 4u : 0u);
	req.sample_count = READ_ONCE(dfm_gyro_sample_count);
	memcpy(req.samples, dfm_gyro_samples, sizeof(req.samples));
	req.direct_events = (u32)atomic64_read(&dfm_gyro_direct_events);
	req.direct_writes = (u32)atomic64_read(&dfm_gyro_direct_writes);
	req.direct_addr = (u64)dfm_gyro_direct_base;
	mutex_unlock(&dfm_gyro_lock);

	if (ret)
		return ret;
	if (copy_to_user(arg, &req, sizeof(req)))
		return -EFAULT;
	return 0;
}
