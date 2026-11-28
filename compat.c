#define pr_fmt(fmt) fmt
#include "dfm_log.h"

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/cred.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/namei.h>
#include <linux/task_work.h>
#include <linux/security.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <asm/cacheflush.h>
#include <asm/fixmap.h>
#include <asm/pgtable.h>

#include "compat.h"

/*
 * Runtime-resolved kernel interfaces (see compat.h).
 *
 * These pointer objects must live in the module: dfm_compat_init() fills them
 * with addresses looked up through kallsyms, so the module carries no
 * undefined references to non-exported GKI symbols.  Dropping these
 * definitions turns every dfm_* name back into an undefined symbol and insmod
 * fails with "Unknown symbol dfm_..." on Android GKI kernels.
 */
unsigned long (*dfm_kallsyms_lookup_name)(const char *name);
int (*dfm_kallsyms_lookup_size_offset)(unsigned long addr, unsigned long *size,
				       unsigned long *offset);
__typeof__(&override_creds) dfm_override_creds;
__typeof__(&revert_creds) dfm_revert_creds;
__typeof__(&kernel_read) dfm_kernel_read;
__typeof__(&kernel_write) dfm_kernel_write;
int (*dfm_task_work_add)(struct task_struct *task,
			 struct callback_head *work,
			 enum task_work_notify_mode notify);
struct file *(*dfm_filp_open)(const char *name, int flags, umode_t mode);
struct vm_struct *(*dfm_get_vm_area_caller)(unsigned long size,
					    unsigned long flags,
					    const void *caller);
int (*dfm_apply_to_page_range)(struct mm_struct *mm, unsigned long addr,
			       unsigned long size, pte_fn_t fn, void *data);
void (*dfm_free_vm_area)(struct vm_struct *area);
void (*dfm___sync_icache_dcache)(pte_t pte);
void (*dfm___set_fixmap)(enum fixed_addresses idx, phys_addr_t phys,
			 pgprot_t prot);
long (*dfm_copy_to_kernel_nofault)(void *dst, const void *src, size_t size);
void (*dfm_dcache_clean_inval_poc)(unsigned long start, unsigned long end);
int (*dfm_set_security_override_from_ctx)(struct cred *cred, const char *secctx);
struct file *(*dfm_get_task_exe_file)(struct task_struct *task);
struct group_info *(*dfm_groups_alloc)(int gidsetsize);
int (*dfm_groups_search)(const struct group_info *group_info, kgid_t grp);
void (*dfm_groups_sort)(struct group_info *group_info);
int (*dfm_set_current_groups)(struct group_info *group_info);
struct mm_struct *dfm_init_mm;
struct pid *(*dfm_get_pid)(struct pid *pid);
void (*dfm_put_pid)(struct pid *pid);
struct pid *(*dfm_find_vpid)(int nr);
struct task_struct *(*dfm_pid_task)(struct pid *pid, enum pid_type type);
unsigned long (*dfm_get_wchan)(struct task_struct *p);
void (*dfm_synchronize_rcu_tasks)(void);
void (*dfm___flush_dcache_area)(void *, size_t);
struct file *(*dfm_fget_task)(struct task_struct *, unsigned int);
void *(*dfm_sock_from_file)(void *, void *);
int (*dfm_init_srcu_struct)(void *);
void (*dfm_cleanup_srcu_struct)(void *);
void (*dfm_synchronize_srcu)(void *);

/*
 * Central symbol table.  Adding a new runtime dependency only requires one
 * entry here plus the matching declaration/macro in compat.h.  Version
 * guards stay next to the entry they apply to instead of being scattered
 * through the resolver function.
 */
struct dfm_compat_symbol {
	const char *name;
	void **slot;
};

static const struct dfm_compat_symbol dfm_compat_symbols[] = {
	{ "kallsyms_lookup_size_offset", (void **)&dfm_kallsyms_lookup_size_offset },
	{ "override_creds", (void **)&dfm_override_creds },
	{ "revert_creds", (void **)&dfm_revert_creds },
	{ "kernel_read", (void **)&dfm_kernel_read },
	{ "kernel_write", (void **)&dfm_kernel_write },
	{ "task_work_add", (void **)&dfm_task_work_add },
	{ "filp_open", (void **)&dfm_filp_open },
	{ "get_vm_area_caller", (void **)&dfm_get_vm_area_caller },
	{ "apply_to_page_range", (void **)&dfm_apply_to_page_range },
	{ "free_vm_area", (void **)&dfm_free_vm_area },
	{ "__sync_icache_dcache", (void **)&dfm___sync_icache_dcache },
	{ "__set_fixmap", (void **)&dfm___set_fixmap },
	{ "copy_to_kernel_nofault", (void **)&dfm_copy_to_kernel_nofault },
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
	{ "dcache_clean_inval_poc", (void **)&dfm_dcache_clean_inval_poc },
#endif
	{ "set_security_override_from_ctx",
	  (void **)&dfm_set_security_override_from_ctx },
	{ "get_task_exe_file", (void **)&dfm_get_task_exe_file },
	{ "groups_alloc", (void **)&dfm_groups_alloc },
	{ "groups_search", (void **)&dfm_groups_search },
	{ "groups_sort", (void **)&dfm_groups_sort },
	{ "set_current_groups", (void **)&dfm_set_current_groups },
	{ "init_mm", (void **)&dfm_init_mm },
	{ "get_pid", (void **)&dfm_get_pid },
	{ "put_pid", (void **)&dfm_put_pid },
	{ "find_vpid", (void **)&dfm_find_vpid },
	{ "pid_task", (void **)&dfm_pid_task },
	{ "get_wchan", (void **)&dfm_get_wchan },
};

unsigned int dfm_compat_missing;

int dfm_compat_init(void)
{
	struct kprobe kp = {
		.symbol_name = "kallsyms_lookup_name",
	};
	unsigned long addr;
	size_t i;
	int ret;

	dfm_compat_missing = 0;
	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_err("cannot resolve kallsyms_lookup_name via kprobe: %d\n",
		       ret);
		dfm_compat_missing = 1;
		return 0;
	}
	dfm_kallsyms_lookup_name = (void *)kp.addr;
	unregister_kprobe(&kp);
	if (!dfm_kallsyms_lookup_name) {
		dfm_compat_missing = 1;
		return 0;
	}

	for (i = 0; i < ARRAY_SIZE(dfm_compat_symbols); i++) {
		const struct dfm_compat_symbol *sym = &dfm_compat_symbols[i];

		addr = dfm_kallsyms_lookup_name(sym->name);
		*sym->slot = (void *)addr;
		if (!addr) {
			pr_err("missing symbol: %s\n", sym->name);
			dfm_compat_missing++;
		}
	}

	if (dfm_compat_missing)
		pr_err("%u compat symbol(s) missing; loading degraded\n",
		       dfm_compat_missing);

	/* Optional symbol: missing on some vendor kernels, fall back to
	 * synchronize_rcu() at the call site instead of failing the load. */
	dfm_synchronize_rcu_tasks =
		(void *)dfm_kallsyms_lookup_name("synchronize_rcu_tasks");
	/* Some 5.10 backports remove the declaration while keeping the symbol;
	 * resolve it at runtime instead of referencing it at compile time. */
	dfm___flush_dcache_area =
		(void *)dfm_kallsyms_lookup_name("__flush_dcache_area");
	dfm_fget_task = (void *)dfm_kallsyms_lookup_name("fget_task");
	dfm_sock_from_file = (void *)dfm_kallsyms_lookup_name("sock_from_file");
	dfm_init_srcu_struct = (void *)dfm_kallsyms_lookup_name("init_srcu_struct");
	dfm_cleanup_srcu_struct =
		(void *)dfm_kallsyms_lookup_name("cleanup_srcu_struct");
	dfm_synchronize_srcu =
		(void *)dfm_kallsyms_lookup_name("synchronize_srcu");

	dfm_info("resolved %zu symbols\n", ARRAY_SIZE(dfm_compat_symbols));
	return 0;
}
