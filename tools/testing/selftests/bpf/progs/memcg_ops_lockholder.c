// SPDX-License-Identifier: GPL-2.0
/*
 * Keep tasks holding a cgroupfs kernfs lock out of inline memory.high
 * enforcement.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

/* cgrp_dfl_root has no BTF variable, so take it as an untyped ksym. */
extern const void cgrp_dfl_root __ksym;

/* Set by resolve_locks() below, before any of the hooks are attached. */
__u64 kernfs_rwsem_addr;
__u64 kernfs_supers_rwsem_addr;

struct lock_state {
	__s32 depth;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct lock_state);
} lock_state SEC(".maps");

/* Charges from a task holding one of the locks: each is a stall avoided. */
__u64 deferrals;
/* Charges from everyone else, where we said nothing. */
__u64 passthroughs;
/* A holder reached inline enforcement anyway.  Must stay zero. */
__u64 violations;
/*
 * A holder went untracked because task storage could not be created.  That
 * looks just like a pass, and gets likelier under the pressure we are
 * testing.  Must stay zero too.
 */
__u64 mark_failures;

/*
 * Find the two rw_semaphores in the cgroup2 kernfs_root.  The loader runs this
 * once before attaching the hooks, so none of them sees a zero address.  Every
 * other kernfs user has its own kernfs_root, hence its own locks, which is
 * what keeps this to cgroupfs.
 */
SEC("syscall")
int resolve_locks(void *ctx)
{
	struct cgroup_root *root = (struct cgroup_root *)&cgrp_dfl_root;
	struct kernfs_root *kf;

	kf = BPF_CORE_READ(root, kf_root);
	if (!kf)
		return 1;

	kernfs_rwsem_addr = (__u64)kf +
		bpf_core_field_offset(struct kernfs_root, kernfs_rwsem);
	kernfs_supers_rwsem_addr = (__u64)kf +
		bpf_core_field_offset(struct kernfs_root, kernfs_supers_rwsem);
	return 0;
}

static __always_inline bool is_cgroup_kernfs_lock(const void *sem)
{
	__u64 addr = (__u64)sem;

	return addr && (addr == kernfs_rwsem_addr ||
			addr == kernfs_supers_rwsem_addr);
}

static __always_inline void note_acquire(const void *sem)
{
	struct lock_state *st;

	if (!is_cgroup_kernfs_lock(sem))
		return;

	st = bpf_task_storage_get(&lock_state, bpf_get_current_task_btf(), NULL,
				  BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!st) {
		__sync_fetch_and_add(&mark_failures, 1);
		return;
	}
	st->depth++;
}

static __always_inline void note_release(const void *sem)
{
	struct lock_state *st;

	if (!is_cgroup_kernfs_lock(sem))
		return;

	st = bpf_task_storage_get(&lock_state, bpf_get_current_task_btf(), NULL, 0);
	if (!st)
		return;
	/* A task already holding it when we attached has no acquire to match. */
	if (st->depth > 0)
		st->depth--;
}

/*
 * down_*() return once the lock is held, so the hold runs from their exit to
 * the entry of up_*().  That excludes the wait.
 *
 * downgrade_write() needs no hook: the lock stays held, and the up_read()
 * after it pairs with the original down_write().
 */

SEC("fexit/down_read")
int BPF_PROG(down_read_exit, struct rw_semaphore *sem)
{
	note_acquire(sem);
	return 0;
}

SEC("fexit/down_write")
int BPF_PROG(down_write_exit, struct rw_semaphore *sem)
{
	note_acquire(sem);
	return 0;
}

/* The killable and interruptible forms return 0 when they got the lock. */
SEC("fexit/down_read_killable")
int BPF_PROG(down_read_killable_exit, struct rw_semaphore *sem, int ret)
{
	if (!ret)
		note_acquire(sem);
	return 0;
}

SEC("fexit/down_read_interruptible")
int BPF_PROG(down_read_interruptible_exit, struct rw_semaphore *sem, int ret)
{
	if (!ret)
		note_acquire(sem);
	return 0;
}

SEC("fexit/down_write_killable")
int BPF_PROG(down_write_killable_exit, struct rw_semaphore *sem, int ret)
{
	if (!ret)
		note_acquire(sem);
	return 0;
}

/* The trylocks return 1 when they got the lock. */
SEC("fexit/down_read_trylock")
int BPF_PROG(down_read_trylock_exit, struct rw_semaphore *sem, int ret)
{
	if (ret == 1)
		note_acquire(sem);
	return 0;
}

SEC("fexit/down_write_trylock")
int BPF_PROG(down_write_trylock_exit, struct rw_semaphore *sem, int ret)
{
	if (ret == 1)
		note_acquire(sem);
	return 0;
}

SEC("fentry/up_read")
int BPF_PROG(up_read_enter, struct rw_semaphore *sem)
{
	note_release(sem);
	return 0;
}

SEC("fentry/up_write")
int BPF_PROG(up_write_enter, struct rw_semaphore *sem)
{
	note_release(sem);
	return 0;
}

/* If a holder gets here, the policy did not work. */
SEC("fentry/__mem_cgroup_handle_over_high")
int BPF_PROG(over_high_enter)
{
	struct lock_state *st;

	st = bpf_task_storage_get(&lock_state, bpf_get_current_task_btf(), NULL, 0);
	if (st && st->depth > 0)
		__sync_fetch_and_add(&violations, 1);
	return 0;
}

/* BPF_PROG() uses "ctx" for the raw argument array, hence "mctx" here. */
SEC("struct_ops")
__u32 BPF_PROG(kernfs_high_policy, const struct bpf_memcg_ctx *mctx)
{
	struct lock_state *st;

	/*
	 * mctx->task is the charging task.  No F_CREATE, so this is just an
	 * RCU read, and the counters are atomics on .bss.  Both are fine here.
	 */
	st = bpf_task_storage_get(&lock_state, mctx->task, NULL, 0);
	if (!st || st->depth <= 0) {
		__sync_fetch_and_add(&passthroughs, 1);
		return BPF_MEMCG_HIGH_NO_OPINION;
	}

	__sync_fetch_and_add(&deferrals, 1);

	/* The kernel ORs this with what the other policies return. */
	return BPF_MEMCG_HIGH_DEFER_INLINE;
}

SEC(".struct_ops.link")
struct bpf_memcg_ops kernfs_lockholder = {
	.high_policy = (void *)kernfs_high_policy,
};
