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
 *  2. tmap: bpf_timer. The delete path must cancel a timer that is still
 *     pending (the delay is tunable through timer_delay_ns so userspace can
 *     arm a long timer and delete the element before it fires), and a
 *     recycled element must be able to arm a fresh timer again.
 *  3. umap: untrusted (unreferenced) kptr. The inherited pointer must be
 *     preserved on recycle, matching hash map behavior.
 *  4. pcmap: per-cpu kptr. Like the referenced kptr, the per-cpu reference
 *     must not be dropped on recycle, and the object's contents must
 *     survive the recycle round-trip.
 *
 * The delete programs check that the element really disappeared, otherwise
 * the following update would be an in-place update whose value copy skips
 * the special fields, and the surviving kptr would prove nothing about the
 * recycle path.
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_experimental.h"
#include "rhtab_fields_common.h"

char LICENSE[] SEC("license") = "GPL";

struct lock_kptr_val {
	struct bpf_spin_lock lock;
	struct task_struct __kptr *tsk;
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
};

struct {
	__uint(type, BPF_MAP_TYPE_RHASH);
	__uint(max_entries, 16);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __u32);
	__type(value, struct timer_val);
} tmap SEC(".maps");

struct unref_val {
	struct task_struct __kptr_untrusted *tsk;
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
	struct pcval __percpu_kptr *pc;
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
	__uint(max_entries, 11);
	__type(key, __u32);
	__type(value, __u64);
} counters SEC(".maps");

/*  0: lk init ok,       1: lk probe xchg non-NULL,  2: lk probe xchg NULL,
 *  3: lk probe magic ok,
 *  4: u init ok,        5: u probe ptr non-NULL,    6: u probe ptr NULL,
 *  7: pc init ok,       8: pc probe xchg non-NULL,  9: pc probe xchg NULL,
 * 10: pc probe data roundtrip
 */
static __always_inline void bump(u32 idx)
{
	u64 *v = bpf_map_lookup_elem(&counters, &idx);

	if (v)
		(*v)++;
}

extern struct task_struct *bpf_task_acquire(struct task_struct *p) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;
extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;

/* Tunable from userspace (an initialized global lands in .data, so the
 * driver writes it through skel->data, not skel->bss).
 */
int timer_delay_ns = 50000;
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

	if (bpf_map_delete_elem(&lkmap, &key))
		return 1;
	/* The element must really be gone: otherwise the following lk_upd()
	 * is an in-place update on the surviving element and the kptr that
	 * lk_probe() then observes never went through a recycle.
	 */
	if (bpf_map_lookup_elem(&lkmap, &key))
		return 2;
	return 0;
}

SEC("syscall")
int lk_upd(void *ctx)
{
	struct lock_kptr_val val = { .magic = LK_MAGIC };
	u32 key = 0;

	/* BPF_ANY is safe even though the value holds a spin lock: value
	 * copies skip special fields, so the lock word is never written and
	 * the prog side does not need to take the lock for an update.
	 */
	bpf_map_update_elem(&lkmap, &key, &val, BPF_ANY);
	return 0;
}

SEC("syscall")
int lk_probe(void *ctx)
{
	struct lock_kptr_val *val;
	struct task_struct *old;
	__u32 magic;
	u32 key = 0;

	val = bpf_map_lookup_elem(&lkmap, &key);
	if (!val)
		return 1;
	/* Take the lock directly: a recycled element that came back with a
	 * corrupted lock word deadlocks here instead of passing. Helpers are
	 * forbidden while the lock is held, so the xchg stays outside.
	 */
	bpf_spin_lock(&val->lock);
	magic = val->magic;
	bpf_spin_unlock(&val->lock);
	old = bpf_kptr_xchg(&val->tsk, NULL);
	if (old) {
		bpf_task_release(old);
		bump(1);
	} else {
		bump(2);
	}
	if (magic == LK_MAGIC)
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
	if (bpf_timer_start(&val->timer, timer_delay_ns, 0))
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

	if (bpf_map_delete_elem(&umap, &key))
		return 1;
	if (bpf_map_lookup_elem(&umap, &key))
		return 2;
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
	else
		bump(6);
	val->tsk = NULL;
	return 0;
}

/* Map 4: per-cpu kptr. */

SEC("syscall")
int pc_init(void *ctx)
{
	struct pcpu_val *val;
	struct pcval *p, *cp, *q, *old;
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
	/* After the xchg the slot holds p, so q aliases p. Syscall progs are
	 * sleepable, so the kptr field load only yields a trusted per-cpu
	 * view under an explicit RCU read lock.
	 */
	bpf_rcu_read_lock();
	q = val->pc;
	if (q) {
		cp = bpf_this_cpu_ptr(q);
		cp->v = PC_MAGIC;
	}
	bpf_rcu_read_unlock();
	bump(7);
	return 0;
}

SEC("syscall")
int pc_del(void *ctx)
{
	u32 key = 0;

	if (bpf_map_delete_elem(&pcmap, &key))
		return 1;
	if (bpf_map_lookup_elem(&pcmap, &key))
		return 2;
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
	struct pcval *cp, *q, *old;
	u32 key = 0;
	int marker = 0;

	val = bpf_map_lookup_elem(&pcmap, &key);
	if (!val)
		return 1;
	/* The object was freshly allocated and marked by pc_init() within
	 * the same iteration, so an inherited object must still carry the
	 * marker; q aliases old until the drop. Read the marker under the
	 * RCU read lock (which makes the field load trusted) and before the
	 * xchg NULLs the field. The read is CPU-local and the loop may
	 * migrate between CPUs, so userspace only asserts that this fired
	 * at least once.
	 */
	bpf_rcu_read_lock();
	q = val->pc;
	if (q) {
		cp = bpf_this_cpu_ptr(q);
		if (cp->v == PC_MAGIC)
			marker = 1;
	}
	bpf_rcu_read_unlock();
	old = bpf_kptr_xchg(&val->pc, NULL);
	if (old) {
		if (marker)
			bump(10);
		bpf_percpu_obj_drop(old);
		bump(8);
	} else {
		bump(9);
	}
	return 0;
}
