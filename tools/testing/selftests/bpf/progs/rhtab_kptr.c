// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 KylinSoft Co., Ltd. */

/*
 * Verify that the rhtab update/delete recycle paths do not eagerly destroy
 * referenced kptrs. rhtab must match the hash map semantics introduced by
 * commit a3a81d247651 ("bpf: Cancel special fields on map value recycle"):
 * only NMI-safe fields (timer, workqueue, task_work) are cancelled on
 * update/delete, while kptrs stay attached to the recycled element until it
 * is eventually freed.
 *
 * Two paths are exercised:
 *  1. a perf_event (NMI) program overwrites an existing element; without the
 *     fix the NMI update releases the old kptr and probe_elem() observes
 *     NULL;
 *  2. the element is deleted and re-inserted; the re-insertion may recycle
 *     the freed element, and zeroing the inherited kptr slot (as
 *     check_and_init_map_value() did before the fix) would drop the
 *     reference without releasing it. probe_elem() must observe the
 *     inherited non-NULL pointer, and plain (non-special) value bytes must
 *     still round-trip through the recycled element.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct val_t {
	struct task_struct __kptr * tsk;
	__u32 magic;
};

struct {
	__uint(type, BPF_MAP_TYPE_RHASH);
	__uint(max_entries, 16);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __u32);
	__type(value, struct val_t);
} rhtab SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 5);
	__type(key, __u32);
	__type(value, __u64);
} counters SEC(".maps");

/* 0: init ok, 1: nmi update ok, 2: probe xchg non-NULL, 3: probe xchg NULL,
 * 4: probe saw expected magic value
 */
static __always_inline void bump(u32 idx)
{
	u64 *v = bpf_map_lookup_elem(&counters, &idx);

	if (v)
		(*v)++;
}

extern struct task_struct *bpf_task_acquire(struct task_struct *p) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;

SEC("perf_event")
int nmi_update(struct bpf_perf_event_data *ctx)
{
	struct val_t val = {};
	u32 key = 0;

	if (bpf_map_update_elem(&rhtab, &key, &val, BPF_ANY) == 0)
		bump(1);
	return 0;
}

SEC("syscall")
int init_elem(void *ctx)
{
	struct val_t *val;
	struct task_struct *task, *old;
	u32 key = 0;

	val = bpf_map_lookup_elem(&rhtab, &key);
	if (!val)
		return 1;
	task = bpf_task_acquire(bpf_get_current_task_btf());
	if (!task)
		return 2;
	old = bpf_kptr_xchg(&val->tsk, task);
	if (old)
		bpf_task_release(old);
	bump(0);
	return 0;
}

SEC("syscall")
int del_elem(void *ctx)
{
	u32 key = 0;

	bpf_map_delete_elem(&rhtab, &key);
	return 0;
}

SEC("syscall")
int upd_elem(void *ctx)
{
	struct val_t val = { .magic = 0x52484153 }; /* "RHAS" */
	u32 key = 0;

	bpf_map_update_elem(&rhtab, &key, &val, BPF_ANY);
	return 0;
}

SEC("syscall")
int probe_elem(void *ctx)
{
	struct val_t *val;
	struct task_struct *old;
	u32 key = 0;

	val = bpf_map_lookup_elem(&rhtab, &key);
	if (!val)
		return 1;
	old = bpf_kptr_xchg(&val->tsk, NULL);
	if (old) {
		bpf_task_release(old);
		bump(2);
	} else {
		bump(3);
	}
	if (val->magic == 0x52484153)
		bump(4);
	return 0;
}
