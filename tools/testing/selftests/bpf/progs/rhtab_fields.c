// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 KylinSoft Co., Ltd. */

/*
 * Combined special-field tests for BPF_MAP_TYPE_RHASH. Each map carries a
 * different field combination and is exercised through delete/re-insert
 * cycles so the bpf memory allocator recycles element memory:
 *
 *  1. lkmap: bpf_spin_lock + referenced kptr + plain data in one value.
 *     After every recycle the spin lock must still be usable (initialized by
 *     the alloc path), the referenced kptr must be inherited instead of
 *     zeroed (zeroing would leak the reference), and the plain bytes must
 *     round-trip.
 *  2. tmap: bpf_timer. The delete path must cancel the timer, and a recycled
 *     element must be able to arm a fresh timer again.
 *  3. umap: untrusted (unreferenced) kptr. The inherited pointer must be
 *     preserved on recycle, matching hash map behavior.
 *  4. pcmap: per-cpu kptr. Like the referenced kptr, the per-cpu reference
 *     must not be dropped on recycle.
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_experimental.h"

char LICENSE[] SEC("license") = "GPL";

struct lock_kptr_val {
	struct bpf_spin_lock lock;
	struct task_struct __kptr * tsk;
	__u32 magic;
};

struct {
	__uint(type, BPF_MAP_TYPE_RHASH);
	__uint(max_entries, 16);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __u32);
	__type(value, struct lock_kptr_val);
} lkmap SEC(".maps");

struct timer_val {
	struct bpf_timer timer;
	__u64 data;
};

struct {
	__uint(type, BPF_MAP_TYPE_RHASH);
	__uint(max_entries, 16);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __u32);
	__type(value, struct timer_val);
} tmap SEC(".maps");

struct unref_val {
	struct task_struct __kptr_untrusted * tsk;
};

struct {
	__uint(type, BPF_MAP_TYPE_RHASH);
	__uint(max_entries, 16);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __u32);
	__type(value, struct unref_val);
} umap SEC(".maps");

struct pcval {
	__u64 v;
};

struct pcpu_val {
	struct pcval __percpu_kptr * pc;
};

struct {
	__uint(type, BPF_MAP_TYPE_RHASH);
	__uint(max_entries, 16);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __u32);
	__type(value, struct pcpu_val);
} pcmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 9);
	__type(key, __u32);
	__type(value, __u64);
} counters SEC(".maps");

/* 0: lk init ok, 1: lk probe xchg non-NULL, 2: lk probe xchg NULL,
 * 3: lk probe magic ok, 4: u init ok, 5: u probe ptr non-NULL,
 * 6: pc init ok, 7: pc probe xchg non-NULL, 8: pc probe xchg NULL
 */
static __always_inline void bump(u32 idx)
{
	u64 *v = bpf_map_lookup_elem(&counters, &idx);

	if (v)
		(*v)++;
}

extern struct task_struct *bpf_task_acquire(struct task_struct *p) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;

int timer_fired;

/* Map 1: spin lock + referenced kptr + plain data. */

SEC("syscall")
int lk_init(void *ctx)
{
	struct lock_kptr_val *val;
	struct task_struct *task, *old;
	u32 key = 0;

	val = bpf_map_lookup_elem(&lkmap, &key);
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
int lk_del(void *ctx)
{
	u32 key = 0;

	bpf_map_delete_elem(&lkmap, &key);
	return 0;
}

SEC("syscall")
int lk_upd(void *ctx)
{
	struct lock_kptr_val val = { .magic = 0x52484142 };
	u32 key = 0;

	bpf_map_update_elem(&lkmap, &key, &val, BPF_ANY);
	return 0;
}

SEC("syscall")
int lk_probe(void *ctx)
{
	struct lock_kptr_val *val;
	struct task_struct *old;
	u32 key = 0;

	val = bpf_map_lookup_elem(&lkmap, &key);
	if (!val)
		return 1;
	old = bpf_kptr_xchg(&val->tsk, NULL);
	if (old) {
		bpf_task_release(old);
		bump(1);
	} else {
		bump(2);
	}
	if (val->magic == 0x52484142)
		bump(3);
	return 0;
}

/* Map 2: bpf_timer. */

static int timer_cb(void *map, void *key, struct timer_val *value)
{
	timer_fired++;
	return 0;
}

SEC("syscall")
int arm_timer(void *ctx)
{
	struct timer_val *val;
	u32 key = 0;

	val = bpf_map_lookup_elem(&tmap, &key);
	if (!val)
		return 1;
	/* 1 == CLOCK_MONOTONIC */
	if (bpf_timer_init(&val->timer, &tmap, 1))
		return 2;
	bpf_timer_set_callback(&val->timer, timer_cb);
	if (bpf_timer_start(&val->timer, 50000, 0))
		return 3;
	return 0;
}

/* Map 3: untrusted kptr. */

SEC("syscall")
int u_init(void *ctx)
{
	struct unref_val *val;
	u32 key = 0;

	val = bpf_map_lookup_elem(&umap, &key);
	if (!val)
		return 1;
	val->tsk = bpf_get_current_task_btf();
	bump(4);
	return 0;
}

SEC("syscall")
int u_del(void *ctx)
{
	u32 key = 0;

	bpf_map_delete_elem(&umap, &key);
	return 0;
}

SEC("syscall")
int u_upd(void *ctx)
{
	struct unref_val val = {};
	u32 key = 0;

	bpf_map_update_elem(&umap, &key, &val, BPF_ANY);
	return 0;
}

SEC("syscall")
int u_probe(void *ctx)
{
	struct unref_val *val;
	u32 key = 0;

	val = bpf_map_lookup_elem(&umap, &key);
	if (!val)
		return 1;
	if (val->tsk)
		bump(5);
	val->tsk = NULL;
	return 0;
}

/* Map 4: per-cpu kptr. */

SEC("syscall")
int pc_init(void *ctx)
{
	struct pcpu_val *val;
	struct pcval *p, *old;
	u32 key = 0;

	val = bpf_map_lookup_elem(&pcmap, &key);
	if (!val)
		return 1;
	p = bpf_percpu_obj_new(struct pcval);
	if (!p)
		return 2;
	old = bpf_kptr_xchg(&val->pc, p);
	if (old)
		bpf_percpu_obj_drop(old);
	bump(6);
	return 0;
}

SEC("syscall")
int pc_del(void *ctx)
{
	u32 key = 0;

	bpf_map_delete_elem(&pcmap, &key);
	return 0;
}

SEC("syscall")
int pc_upd(void *ctx)
{
	struct pcpu_val val = {};
	u32 key = 0;

	bpf_map_update_elem(&pcmap, &key, &val, BPF_ANY);
	return 0;
}

SEC("syscall")
int pc_probe(void *ctx)
{
	struct pcpu_val *val;
	struct pcval *old;
	u32 key = 0;

	val = bpf_map_lookup_elem(&pcmap, &key);
	if (!val)
		return 1;
	old = bpf_kptr_xchg(&val->pc, NULL);
	if (old) {
		bpf_percpu_obj_drop(old);
		bump(7);
	} else {
		bump(8);
	}
	return 0;
}
