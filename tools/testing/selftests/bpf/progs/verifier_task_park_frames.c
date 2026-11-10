// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include "bpf_experimental.h"
#include <errno.h>
#include "bpf_misc.h"

/* Where a bpf_task_park() may sit in the call graph, and what its callers lose. */
char _license[] SEC("license") = "GPL";

struct park_elem {
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

struct wq_elem {
	struct bpf_wq wq;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct wq_elem);
} wq_map SEC(".maps");

struct tw_elem {
	struct bpf_task_work tw;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct tw_elem);
} tw_map SEC(".maps");

static __always_inline struct park_elem *lookup_hash_elem(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&hash_map, &key);
}

/* A static function that parks is verified in its caller's state: the park sees every frame. */
static __noinline int park_static(void)
{
	return bpf_task_park(0, 0);
}

/* A global function is verified alone: its callers rely on the might_park mark. */
__noinline int park_global(void)
{
	return bpf_task_park(0, 0);
}

/* The mark reaches callers through further static and global functions. */
static __noinline int park_via_static(void)
{
	return park_global();
}

__noinline int park_via_global(void)
{
	return park_global();
}

/* The mark reaches a caller that sleeps on its own account as well. */
__noinline int park_and_sleep_global(void)
{
	char buf[8];

	park_static();
	return bpf_copy_from_user(buf, sizeof(buf), NULL);
}

/* A park in a function called directly from the main program is allowed. */
SEC("syscall")
__success __retval(0)
int park_in_static_subprog(void *ctx)
{
	return park_static() != -ETIMEDOUT;
}

SEC("syscall")
__success __retval(0)
int park_in_global_subprog(void *ctx)
{
	return park_global() != -ETIMEDOUT;
}

/* The caller's hash map value does not survive a park in its callee, static or global. */
SEC("syscall")
__failure __msg("invalid mem access 'scalar'")
int hash_value_after_static_subprog_park(void *ctx)
{
	struct park_elem *elem = lookup_hash_elem();

	if (!elem)
		return 0;
	park_static();
	return elem->state;
}

SEC("syscall")
__failure __msg("invalid mem access 'scalar'")
int hash_value_after_global_subprog_park(void *ctx)
{
	struct park_elem *elem = lookup_hash_elem();

	if (!elem)
		return 0;
	park_global();
	return elem->state;
}

SEC("syscall")
__failure __msg("invalid mem access 'scalar'")
int hash_value_after_nested_subprog_park(void *ctx)
{
	struct park_elem *elem = lookup_hash_elem();

	if (!elem)
		return 0;
	park_via_static();
	return elem->state;
}

SEC("syscall")
__failure __msg("invalid mem access 'scalar'")
int hash_value_after_sleeping_subprog_park(void *ctx)
{
	struct park_elem *elem = lookup_hash_elem();

	if (!elem)
		return 0;
	park_and_sleep_global();
	return elem->state;
}

/* A dynptr held by the caller is as live across a global call that parks as across the park. */
char dynptr_buf[8];

SEC("syscall")
__failure __msg("bpf_task_park() with a live dynptr at frame 0")
int dynptr_across_global_subprog_park(void *ctx)
{
	struct bpf_dynptr ptr;

	bpf_dynptr_from_mem(dynptr_buf, sizeof(dynptr_buf), 0, &ptr);
	park_global();
	return 0;
}

SEC("syscall")
__failure __msg("bpf_task_park() with a live bits iterator at frame 0")
int bits_iterator_across_global_subprog_park(void *ctx)
{
	struct bpf_iter_bits it;
	__u64 word = 1;

	bpf_iter_bits_new(&it, &word, 1);
	park_global();
	bpf_iter_bits_destroy(&it);
	return 0;
}

/*
 * No callback other than the body of a BPF kthread may park: not directly, not
 * through a static or a global function.
 */
static int park_cb(__u32 index, void *data)
{
	bpf_task_park(0, 0);
	return 1;
}

SEC("syscall")
__failure __msg("bpf_task_park() is not allowed in a callback")
int park_in_loop_callback(void *ctx)
{
	bpf_loop(1, park_cb, NULL, 0);
	return 0;
}

static int park_static_cb(__u32 index, void *data)
{
	park_static();
	return 1;
}

SEC("syscall")
__failure __msg("bpf_task_park() is not allowed in a callback")
int static_subprog_park_in_callback(void *ctx)
{
	bpf_loop(1, park_static_cb, NULL, 0);
	return 0;
}

static int park_global_cb(__u32 index, void *data)
{
	park_global();
	return 1;
}

SEC("syscall")
__failure __msg("global function park_global() may call bpf_task_park(), "
		"which is not allowed in a callback")
int global_subprog_park_in_callback(void *ctx)
{
	bpf_loop(1, park_global_cb, NULL, 0);
	return 0;
}

static int park_via_global_cb(__u32 index, void *data)
{
	park_via_global();
	return 1;
}

SEC("syscall")
__failure __msg("global function park_via_global() may call bpf_task_park(), "
		"which is not allowed in a callback")
int nested_global_subprog_park_in_callback(void *ctx)
{
	bpf_loop(1, park_via_global_cb, NULL, 0);
	return 0;
}

static int park_for_each_cb(struct bpf_map *map, __u32 *key, struct park_elem *val, void *data)
{
	bpf_task_park(0, 0);
	return 1;
}

SEC("syscall")
__failure __msg("bpf_task_park() is not allowed in a callback")
int park_in_for_each_callback(void *ctx)
{
	bpf_for_each_map_elem(&park_map, park_for_each_cb, NULL, 0);
	return 0;
}

#ifdef CAN_USE_CALLX

/* calls_arg(fn) { return fn(); } */
__naked __noinline __used
static unsigned long calls_arg(void)
{
	asm volatile ("					\
	callx r1;					\
	exit;						\
"	::: __clobber_all);
}

/*
 * The program loads the address of the function that parks, calls_arg() calls
 * it. Nothing marks calls_arg(), so it is verified on its own, without its
 * callers, until its exit says that it parked. The hash map value of the
 * program is gone after the call all the same.
 */
SEC("syscall")
__failure __msg("invalid mem access 'scalar'")
__naked int hash_value_after_callx_park(void)
{
	asm volatile ("					\
	r1 = 0;						\
	*(u32 *)(r10 - 4) = r1;				\
	r2 = r10;					\
	r2 += -4;					\
	r1 = %[hash_map] ll;				\
	call %[bpf_map_lookup_elem];			\
	if r0 == 0 goto l0_%=;				\
	r6 = r0;					\
	r1 = %[park_static] ll;				\
	call calls_arg;					\
	r0 = *(u32 *)(r6 + %[state_off]);		\
l0_%=:	exit;						\
"	:
	: __imm(bpf_map_lookup_elem),
	  __imm_addr(hash_map),
	  __imm_addr(park_static),
	  __imm_const(state_off, offsetof(struct park_elem, state))
	: __clobber_all);
}

/* Nor does the callback get to park behind calls_arg(). */
__naked __noinline __used
static unsigned long park_callx_cb(void)
{
	asm volatile ("					\
	r1 = %[park_static] ll;				\
	call calls_arg;					\
	r0 = 1;						\
	exit;						\
"	:
	: __imm_addr(park_static)
	: __clobber_all);
}

SEC("syscall")
__failure __msg("bpf_task_park() is not allowed in a callback")
__naked int callx_park_in_callback(void)
{
	asm volatile ("					\
	r1 = 1;						\
	r2 = %[park_callx_cb] ll;			\
	r3 = 0;						\
	r4 = 0;						\
	call %[bpf_loop];				\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_loop),
	  __imm_addr(park_callx_cb)
	: __clobber_all);
}

#endif /* CAN_USE_CALLX */

/* An asynchronous callback is verified as its own state, with the callback as frame 0. */
static int park_wq_cb(void *map, int *key, void *value)
{
	bpf_task_park(0, 0);
	return 0;
}

SEC("syscall")
__failure __msg("bpf_task_park() is not allowed in a callback")
int park_in_wq_callback(void *ctx)
{
	struct wq_elem *elem;
	__u32 key = 0;

	elem = bpf_map_lookup_elem(&wq_map, &key);
	if (!elem)
		return 0;
	if (bpf_wq_init(&elem->wq, &wq_map, 0))
		return 0;
	if (bpf_wq_set_callback(&elem->wq, park_wq_cb, 0))
		return 0;
	return bpf_wq_start(&elem->wq, 0);
}

static int park_task_work_cb(struct bpf_map *map, void *key, void *value)
{
	bpf_task_park(0, 0);
	return 0;
}

SEC("syscall")
__failure __msg("bpf_task_park() is not allowed in a callback")
int park_in_task_work_callback(void *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct tw_elem *elem;
	__u32 key = 0;

	elem = bpf_map_lookup_elem(&tw_map, &key);
	if (!elem)
		return 0;
	return bpf_task_work_schedule_signal(task, &elem->tw, &tw_map, park_task_work_cb);
}

/* The exception callback unwinds the program after bpf_throw(): no park there either. */
__noinline int park_exception_cb(u64 cookie)
{
	bpf_task_park(0, 0);
	return 0;
}

SEC("syscall")
__exception_cb(park_exception_cb)
__arch_x86_64 __arch_arm64 __arch_s390x
__failure __msg("bpf_task_park() is not allowed in a callback")
int park_in_exception_callback(void *ctx)
{
	bpf_throw(0);
	return 0;
}
