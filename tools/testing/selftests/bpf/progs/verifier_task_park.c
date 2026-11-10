// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#define BPF_NO_KFUNC_PROTOTYPES
#include <vmlinux.h>
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"
#include <bpf_arena_common.h>

/* What survives a bpf_task_park(), what does not, and where the park is refused. */
char _license[] SEC("license") = "GPL";

extern struct task_struct *bpf_task_acquire(struct task_struct *task) __ksym;
extern void bpf_task_release(struct task_struct *task) __ksym;
extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;
extern void bpf_local_irq_save(unsigned long *flags) __weak __ksym;
extern void bpf_local_irq_restore(unsigned long *flags) __weak __ksym;
extern int bpf_res_spin_lock(struct bpf_res_spin_lock *lock) __weak __ksym;
extern void bpf_res_spin_unlock(struct bpf_res_spin_lock *lock) __weak __ksym;
extern int bpf_iter_bits_new(struct bpf_iter_bits *it, const u64 *unsafe_ptr__ign,
			     u32 nr_words) __weak __ksym;
extern void bpf_iter_bits_destroy(struct bpf_iter_bits *it) __weak __ksym;

struct park_elem {
	struct bpf_spin_lock lock;
	struct task_struct __kptr *task;
	struct task_struct __kptr_untrusted *untrusted_task;
	__u32 state;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct park_elem);
} park_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct park_elem);
} hash_map SEC(".maps");

struct rlock_elem {
	struct bpf_res_spin_lock lock;
	__u32 state;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct rlock_elem);
} rlock_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
	__array(values, struct {
		__uint(type, BPF_MAP_TYPE_ARRAY);
		__uint(max_entries, 1);
		__type(key, __u32);
		__type(value, __u32);
	});
} outer_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} ringbuf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 2);
} arena SEC(".maps");

static __always_inline struct park_elem *lookup_elem(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&park_map, &key);
}

/*
 * A hash map frees a deleted element after a grace period the sleeper no
 * longer delays: its value is gone after a park, in a register or spilled.
 */
SEC("syscall")
__failure __msg("invalid mem access 'scalar'")
int hash_value_after_park(void *ctx)
{
	struct park_elem *elem;
	__u32 key = 0;

	elem = bpf_map_lookup_elem(&hash_map, &key);
	if (!elem)
		return 0;
	bpf_task_park(0, 0);
	return elem->state;
}

SEC("syscall")
__failure __msg("invalid mem access 'scalar'")
__naked int spilled_hash_value_after_park(void)
{
	asm volatile ("					\
	r1 = 0;						\
	*(u32 *)(r10 - 4) = r1;				\
	r2 = r10;					\
	r2 += -4;					\
	r1 = %[hash_map] ll;				\
	call %[bpf_map_lookup_elem];			\
	if r0 == 0 goto l0_%=;				\
	*(u64 *)(r10 - 16) = r0;			\
	r1 = 0;						\
	r2 = 0;						\
	call bpf_task_park;				\
	r6 = *(u64 *)(r10 - 16);			\
	r0 = *(u32 *)(r6 + %[state_off]);		\
l0_%=:	exit;						\
"	:
	: __imm(bpf_map_lookup_elem),
	  __imm_addr(hash_map),
	  __imm_const(state_off, offsetof(struct park_elem, state))
	: __clobber_all);
}

/* An array allocates its values with the map, which the program holds: they survive. */
SEC("syscall")
__success __retval(0)
int array_value_survives_park(void *ctx)
{
	struct park_elem *elem = lookup_elem();

	if (!elem)
		return 1;
	bpf_task_park(0, 0);
	return elem->state;
}

/*
 * Global variables are array values too, and the compiler hoists their address
 * out of loops; whether it does is its choice, so the hoisted form is pinned in
 * assembly as well.
 */
__u32 rounds = 2;

SEC("syscall")
__success __retval(0)
int global_survives_park_in_loop(void *ctx)
{
	__u32 i, n = 0;

	for (i = 0; i < 4 && i < rounds; i++) {
		bpf_task_park(0, 0);
		n++;
	}
	return n != 2;
}

SEC("syscall")
__success __retval(2)
__naked int global_pointer_survives_park(void)
{
	asm volatile ("					\
	r6 = %[rounds] ll;				\
	r1 = 0;						\
	r2 = 0;						\
	call bpf_task_park;				\
	r0 = *(u32 *)(r6 + 0);				\
	exit;						\
"	:
	: __imm_addr(rounds)
	: __clobber_all);
}

/* A per-CPU value is gone: the task may resume on another CPU. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} percpu_map SEC(".maps");

SEC("syscall")
__failure __msg("invalid mem access 'scalar'")
int percpu_value_after_park(void *ctx)
{
	__u32 key = 0, *val;

	val = bpf_map_lookup_elem(&percpu_map, &key);
	if (!val)
		return 0;
	bpf_task_park(0, 0);
	return *val;
}

/* A trusted but unreferenced pointer is gone after a park. */
SEC("syscall")
__failure __msg("invalid mem access 'scalar'")
int task_pointer_after_park(void *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();

	bpf_task_park(0, 0);
	return task->pid;
}

/* A referenced pointer survives a park. */
SEC("syscall")
__success __retval(0)
int referenced_task_survives_park(void *ctx)
{
	struct task_struct *task;

	task = bpf_task_acquire(bpf_get_current_task_btf());
	if (!task)
		return 1;
	bpf_task_park(0, 0);
	bpf_task_release(task);
	return 0;
}

/* The stack and the context belong to the invocation: both survive a park. */
SEC("syscall")
__success __retval(7)
int stack_survives_park(void *ctx)
{
	volatile __u32 word = 7;

	bpf_task_park(0, 0);
	return word;
}

/*
 * Load only: the runner refuses a context smaller than the program reads, and
 * the loader passes none.
 */
SEC("syscall")
__success
int ctx_survives_park(__u32 *ctx)
{
	bpf_task_park(0, 0);
	return *ctx;
}

/* Arena memory is held by the arena map, which the program holds: it survives a park. */
SEC("syscall")
__success __retval(0)
int arena_pointer_survives_park(void *ctx)
{
#if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
	volatile int __arena *page;

	page = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
	if (!page)
		return 1;
	*page = 7;
	bpf_task_park(0, 0);
	return *page != 7;
#else
	/* Nothing to test without arena casts; the program must still load. */
	return 0;
#endif
}

/* A map the program references directly is held by the invocation: its pointer survives. */
SEC("syscall")
__success __retval(0)
__naked int map_pointer_survives_park(void)
{
	asm volatile ("					\
	r6 = %[park_map] ll;				\
	r1 = 0;						\
	r2 = 0;						\
	call bpf_task_park;				\
	r1 = 0;						\
	*(u32 *)(r10 - 4) = r1;				\
	r2 = r10;					\
	r2 += -4;					\
	r1 = r6;					\
	call %[bpf_map_lookup_elem];			\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_map_lookup_elem),
	  __imm_addr(park_map)
	: __clobber_all);
}

/*
 * An inner map is held only by the outer map's element: neither its pointer
 * nor its values survive, even though the inner map is an array.
 */
SEC("syscall")
__failure __msg("expected=map_ptr")
int inner_map_pointer_after_park(void *ctx)
{
	__u32 key = 0;
	void *inner;

	inner = bpf_map_lookup_elem(&outer_map, &key);
	if (!inner)
		return 0;
	bpf_task_park(0, 0);
	return bpf_map_lookup_elem(inner, &key) != NULL;
}

SEC("syscall")
__failure __msg("invalid mem access 'scalar'")
int inner_array_value_after_park(void *ctx)
{
	__u32 key = 0, *val;
	void *inner;

	inner = bpf_map_lookup_elem(&outer_map, &key);
	if (!inner)
		return 0;
	val = bpf_map_lookup_elem(inner, &key);
	if (!val)
		return 0;
	bpf_task_park(0, 0);
	return *val;
}

/* A dynptr on the stack is refused across a park, referenced or not. */
char dynptr_buf[8];

SEC("syscall")
__failure __msg("bpf_task_park() with a live dynptr at frame 0")
int dynptr_across_park(void *ctx)
{
	struct bpf_dynptr ptr;

	bpf_dynptr_from_mem(dynptr_buf, sizeof(dynptr_buf), 0, &ptr);
	bpf_task_park(0, 0);
	return 0;
}

SEC("syscall")
__failure __msg("bpf_task_park() with a live dynptr at frame 0")
int ringbuf_dynptr_across_park(void *ctx)
{
	struct bpf_dynptr ptr;

	bpf_ringbuf_reserve_dynptr(&ringbuf, 8, 0, &ptr);
	bpf_task_park(0, 0);
	bpf_ringbuf_discard_dynptr(&ptr, 0);
	return 0;
}

/* A number iterator lives entirely on the stack: a park inside the loop is fine. */
SEC("syscall")
__success __retval(0)
int num_iterator_survives_park(void *ctx)
{
	int i;

	bpf_for(i, 0, 3)
		bpf_task_park(0, 0);
	return 0;
}

/* Any other iterator is refused across a park. */
SEC("syscall")
__failure __msg("bpf_task_park() with a live bits iterator at frame 0")
int bits_iterator_across_park(void *ctx)
{
	struct bpf_iter_bits it;
	__u64 word = 1;

	bpf_iter_bits_new(&it, &word, 1);
	bpf_task_park(0, 0);
	bpf_iter_bits_destroy(&it);
	return 0;
}

/* Regions that pin the CPU or hold a lock refuse a sleepable call, the park included. */
SEC("syscall")
__failure __msg("function calls are not allowed while holding a lock")
int park_while_locked(void *ctx)
{
	struct park_elem *elem = lookup_elem();

	if (!elem)
		return 0;
	bpf_spin_lock(&elem->lock);
	bpf_task_park(0, 0);
	bpf_spin_unlock(&elem->lock);
	return 0;
}

SEC("syscall")
__failure __msg("function calls are not allowed while holding a lock")
int park_while_res_locked(void *ctx)
{
	struct rlock_elem *elem;
	__u32 key = 0;

	elem = bpf_map_lookup_elem(&rlock_map, &key);
	if (!elem)
		return 0;
	if (bpf_res_spin_lock(&elem->lock))
		return 0;
	bpf_task_park(0, 0);
	bpf_res_spin_unlock(&elem->lock);
	return 0;
}

SEC("syscall")
__failure __msg("kernel func bpf_task_park is sleepable within rcu_read_lock region")
int park_in_rcu_region(void *ctx)
{
	bpf_rcu_read_lock();
	bpf_task_park(0, 0);
	bpf_rcu_read_unlock();
	return 0;
}

SEC("syscall")
__failure __msg("kernel func bpf_task_park is sleepable within non-preemptible region")
int park_in_preempt_disabled_region(void *ctx)
{
	bpf_preempt_disable();
	bpf_task_park(0, 0);
	bpf_preempt_enable();
	return 0;
}

SEC("syscall")
__failure __msg("kernel func bpf_task_park is sleepable within IRQ-disabled region")
int park_in_irq_disabled_region(void *ctx)
{
	unsigned long flags;

	bpf_local_irq_save(&flags);
	bpf_task_park(0, 0);
	bpf_local_irq_restore(&flags);
	return 0;
}

/*
 * The time slice of may_goto is kept per CPU, and a program that parks may go
 * on on another one. That holds for a may_goto the program asks for and for one
 * the verifier adds to a loop it cannot bound.
 */
SEC("syscall")
__failure __msg("may_goto cannot be used in a program that may migrate")
int park_with_may_goto(void *ctx)
{
	int i;

	for (i = 0; i < 4 && can_loop; i++)
		bpf_task_park(0, 0);
	return 0;
}

SEC("syscall")
__failure __msg("may_goto cannot be used in a program that may migrate")
int park_in_unbounded_loop(void *ctx)
{
	while (*(volatile __u32 *)&rounds)
		bpf_task_park(0, 0);
	return 0;
}

/* The park is registered for syscall programs only. */
SEC("tp/syscalls/sys_enter_nanosleep")
__failure __msg("calling kernel function bpf_task_park is not allowed")
int park_from_non_syscall(void *ctx)
{
	return bpf_task_park(0, 0);
}

/* The wake is registered for every program type. */
SEC("xdp")
__success
int wake_from_xdp(void *ctx)
{
	struct park_elem *elem = lookup_elem();
	struct task_struct *task;

	if (!elem)
		return XDP_PASS;
	bpf_rcu_read_lock();
	task = elem->task;
	if (task)
		bpf_task_wake(task, 0);
	bpf_rcu_read_unlock();
	return XDP_PASS;
}

/* bpf_task_wake() takes a referenced, trusted or RCU-protected task that is not NULL. */
SEC("syscall")
__failure __msg("R1 must be a rcu pointer")
int wake_untrusted_task(void *ctx)
{
	struct park_elem *elem = lookup_elem();
	struct task_struct *task;

	if (!elem)
		return 0;
	task = elem->untrusted_task;
	if (!task)
		return 0;
	return bpf_task_wake(task, 0);
}

SEC("syscall")
__failure __msg("Possibly NULL pointer passed to trusted R1")
int wake_maybe_null_task(void *ctx)
{
	struct park_elem *elem = lookup_elem();
	struct task_struct *task;
	int ret;

	if (!elem)
		return 0;
	bpf_rcu_read_lock();
	task = elem->task;
	ret = bpf_task_wake(task, 0);
	bpf_rcu_read_unlock();
	return ret;
}

SEC("syscall")
__success
int wake_rcu_task(void *ctx)
{
	struct park_elem *elem = lookup_elem();
	struct task_struct *task;
	int ret = 0;

	if (!elem)
		return 0;
	bpf_rcu_read_lock();
	task = elem->task;
	if (task)
		ret = bpf_task_wake(task, 0);
	bpf_rcu_read_unlock();
	return ret;
}
