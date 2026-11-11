// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"
#include "../test_kmods/bpf_testmod.h"

#define MAX_RES 8
#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))

struct foo {
	int data;
	struct bpf_list_node node;
};

struct locked_foo {
	int data;
	struct bpf_spin_lock lock;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} ringbuf SEC(".maps");

private(A) struct bpf_spin_lock glock;

/* Resources the program under test acquired, in order. */
__u64 acquired[MAX_RES];
__u32 acquired_cnt;
/* The releases observed, in order: the handle of the resource, or none for a section. */
__u64 released[MAX_RES];
__u8 released_section[MAX_RES];
__u32 released_cnt;
/* The test process: the sections it leaves are the ones under test. */
__u32 test_pid;
/* A choice of the test, read by the program under test. */
__u32 param;

static __always_inline void mark_acquired(void *p)
{
	__u32 i = acquired_cnt;

	if (i < MAX_RES) {
		acquired[i] = (__u64)p;
		acquired_cnt = i + 1;
	}
}

/*
 * Record a release: of @p, one of the resources the program acquired, or,
 * as a @section, of what the program has no handle of: a section of the test
 * process, or the reader of a file dynptr. The hooks fire for every unwind in
 * the system, so releases of other programs are left out.
 */
static __always_inline void mark_released(void *p, bool section)
{
	__u32 i, n = released_cnt;

	if (n >= MAX_RES)
		return;
	if (section) {
		if (bpf_get_current_pid_tgid() >> 32 != test_pid)
			return;
	} else {
		if (!p)
			return;
		for (i = 0; i < MAX_RES; i++)
			if (i < acquired_cnt && acquired[i] == (__u64)p)
				break;
		if (i == MAX_RES)
			return;
	}
	released[n] = section ? 0 : (__u64)p;
	released_section[n] = section;
	released_cnt = n + 1;
}

/*
 * Observe every release the unwinder performs, identified like the program
 * sees it: the handle is the pointer to an object or a record, the address of
 * a stack object or of a lock; a section has none.
 */
SEC("fentry/bpf_unwind_release")
int BPF_PROG(release_hook, struct bpf_resource *res, void *handle)
{
	mark_released(handle, res->kind == BPF_RESOURCE_RCU || res->kind == BPF_RESOURCE_PREEMPT ||
			      res->kind == BPF_RESOURCE_DYNPTR_FILE);
	return 0;
}

/* An object in a callee-saved register of the throwing frame. */
SEC("tc")
int throw_obj_reg(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	if (ctx->len)
		bpf_throw(0xeB9F);
	bpf_obj_drop(f);
	return 0;
}

/* Two objects, one spilled to the stack by the compiler. */
SEC("tc")
int throw_obj_two(struct __sk_buff *ctx)
{
	struct foo *f, *g;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	g = bpf_obj_new(typeof(*g));
	if (!g) {
		bpf_obj_drop(f);
		return 1;
	}
	mark_acquired(f);
	mark_acquired(g);
	if (ctx->len)
		bpf_throw(0xeB9F);
	bpf_obj_drop(f);
	bpf_obj_drop(g);
	return 0;
}

/* A ringbuf reservation. */
SEC("tc")
int throw_ringbuf(struct __sk_buff *ctx)
{
	void *p;

	p = bpf_ringbuf_reserve(&ringbuf, 8, 0);
	if (!p)
		return 1;
	mark_acquired(p);
	if (ctx->len)
		bpf_throw(0xeB9F);
	bpf_ringbuf_discard(p, 0);
	return 0;
}

/* A task reference released through the destructor registry. */
SEC("tc")
int throw_task(struct __sk_buff *ctx)
{
	struct task_struct *t;

	t = bpf_task_acquire(bpf_get_current_task_btf());
	if (!t)
		return 1;
	mark_acquired(t);
	if (ctx->len)
		bpf_throw(0xeB9F);
	bpf_task_release(t);
	return 0;
}

/*
 * The task the kernel passes a struct_ops program in a __ref argument is the
 * program's to release: the unwinder releases it when the program has not.
 */
SEC("struct_ops/test_refcounted")
int BPF_PROG(throw_ops_ref, int dummy, struct task_struct *task)
{
	mark_acquired(task);
	if (param)
		bpf_task_release(task);
	bpf_throw(0);
	return 0;
}

SEC(".struct_ops.link")
struct bpf_testmod_ops throwing_ops = {
	.test_refcounted = (void *)throw_ops_ref,
};

/* Set by the test before the open of a file that the program acts on. */
__u32 file_armed;

/*
 * The file is a referenced object, and the dynptr holds a reader of it that
 * the program has no handle of: the unwinder frees the reader, then puts the
 * file.
 */
SEC("lsm/file_open")
int BPF_PROG(throw_file_dynptr)
{
	struct bpf_dynptr dynptr;
	struct file *file;

	if (!file_armed || bpf_get_current_pid_tgid() >> 32 != test_pid)
		return 0;
	file_armed = 0;
	file = bpf_get_task_exe_file(bpf_get_current_task_btf());
	if (!file)
		return 0;
	mark_acquired(file);
	bpf_dynptr_from_file(file, 0, &dynptr);
	if (param) {
		bpf_dynptr_file_discard(&dynptr);
		bpf_put_file(file);
	}
	bpf_throw(0);
	return 0;
}

/* Port, in network order, of the listener throw_sock_cast looks up. */
__u16 server_port;

/*
 * A socket acquired by a lookup and cast to its struct by a helper, which
 * carries the reference under the struct's type: released as the socket.
 */
SEC("tc")
int throw_sock_cast(struct __sk_buff *ctx)
{
	struct bpf_sock_tuple tuple = {};
	struct bpf_sock *skc;
	struct tcp_sock *tp;

	tuple.ipv4.daddr = bpf_htonl(0x7f000001);
	tuple.ipv4.dport = server_port;
	skc = bpf_skc_lookup_tcp(ctx, &tuple, sizeof(tuple.ipv4), -1, 0);
	if (!skc)
		return 1;
	tp = bpf_skc_to_tcp_sock(skc);
	if (!tp) {
		bpf_sk_release(skc);
		return 1;
	}
	mark_acquired(tp);
	if (ctx->len)
		bpf_throw(0xeB9F);
	bpf_sk_release((struct bpf_sock *)tp);
	return 0;
}

/* An open-coded iterator on the stack. */
SEC("tc")
int throw_iter(struct __sk_buff *ctx)
{
	struct bpf_iter_num it;
	int *v;

	bpf_iter_num_new(&it, 0, 10);
	mark_acquired(&it);
	while ((v = bpf_iter_num_next(&it))) {
		if (*v == 3 && ctx->len)
			bpf_throw(0xeB9F);
	}
	bpf_iter_num_destroy(&it);
	return 0;
}

/* The object is NULL on one path and an object on the other at the throw. */
SEC("tc")
int throw_obj_maybe(struct __sk_buff *ctx)
{
	struct foo *f = NULL;

	if (ctx->len > 1) {
		f = bpf_obj_new(typeof(*f));
		if (!f)
			return 1;
		mark_acquired(f);
	}
	if (ctx->len)
		bpf_throw(0xeB9F);
	if (f)
		bpf_obj_drop(f);
	return 0;
}

static __noinline int throw_in_subprog(struct __sk_buff *ctx, int x)
{
	/* Use callee-saved registers so the caller's are saved in this frame. */
	__u64 a = x * 3, b = x * 5, c = x * 7;

	if (ctx->len)
		bpf_throw(0xeB9F);
	return a + b + c;
}

/* The object is held by the caller of the throwing static subprog. */
SEC("tc")
int throw_obj_caller(struct __sk_buff *ctx)
{
	struct foo *f;
	int ret;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	ret = throw_in_subprog(ctx, ctx->len);
	bpf_obj_drop(f);
	return ret;
}

/* The object is held by the caller across a call of the throwing subprog by its address. */
SEC("tc")
int throw_obj_callx_caller(struct __sk_buff *ctx)
{
	int (*callee)(struct __sk_buff *, int) = throw_in_subprog;
	struct foo *f;
	int ret;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	/* Hide the callee from the compiler, so that the call goes through the pointer: a callx. */
	asm volatile ("" : "+r"(callee));
	ret = callee(ctx, ctx->len);
	bpf_obj_drop(f);
	return ret;
}

/* Allocates at its first insns: the call that acquires is at the start of the subprog. */
static __noinline int alloc_and_throw(void)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (f)
		mark_acquired(f);
	bpf_throw(0xeB9F);
	return 0;
}

/* A count the verifier does not know. */
volatile __u32 loops = 1;

/*
 * The loop gets a may_goto of the verifier's, in front of the subprog that
 * allocates at its first insns: what the main pass named by instruction has
 * to be told from the subprog starts as they are after that.
 */
SEC("tc")
int throw_obj_origin_after_guard(struct __sk_buff *ctx)
{
	__u32 i;

	for (i = 0; i < loops; i++)
		;
	return alloc_and_throw();
}

/* The throw is unconditional, so nothing after it keeps the object alive. */
SEC("tc")
int throw_obj_unconditional(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	bpf_throw(0xeB9F);
	return 0;
}

static __noinline int throw_unconditionally(void)
{
	bpf_throw(0xeB9F);
	return 0;
}

/*
 * The callee's throw is unconditional, so the caller never reads the object
 * again after the call: the object is released from the slot of the caller's
 * frame, which the acquisition filled.
 */
SEC("tc")
int throw_obj_dead_caller(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	return throw_unconditionally();
}

static __noinline int subprog_acquire_throw(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	bpf_throw(0xeB9F);
	return 0;
}

/* The object is acquired and the throw raised in a static subprog. */
SEC("tc")
int throw_obj_subprog(struct __sk_buff *ctx)
{
	return subprog_acquire_throw(ctx) + 1;
}

__noinline int global_throw(struct __sk_buff *ctx)
{
	if (ctx->len)
		bpf_throw(0xeB9F);
	return 0;
}

/* The object is held by the caller of the throwing global subprog. */
SEC("tc")
int throw_obj_global_caller(struct __sk_buff *ctx)
{
	struct foo *f;
	int ret;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	ret = global_throw(ctx);
	bpf_obj_drop(f);
	return ret;
}

/*
 * R6 holds the ringbuf record on one path and a number on the other at the
 * throw: the record is released from the hidden slot of the frame, which the
 * acquisition fills and the release clears, whatever R6 holds.
 */
SEC("tc")
__naked int throw_reg_conflict(void)
{
	asm volatile (
	"r6 = *(u32 *)(r1 + %[len]);"
	"r7 = 0;"
	"if r6 == 0 goto 1f;"
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 3f;"
	"r6 = r0;"
	"r7 = 1;"
	"r1 = %[acquired] ll;"
	"*(u64 *)(r1 + 0) = r0;"
	"r1 = %[acquired_cnt] ll;"
	"*(u32 *)(r1 + 0) = r7;"
	"goto 2f;"
	"1: r6 = 42;"
	"2: r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"if r7 == 0 goto 3f;"
	"r1 = r6;"
	"r2 = 0;"
	"call %[bpf_ringbuf_discard];"
	"3: r0 = 0;"
	"exit;"
	:
	: __imm_addr(ringbuf),
	  __imm_addr(acquired),
	  __imm_addr(acquired_cnt),
	  __imm(bpf_ringbuf_reserve),
	  __imm(bpf_ringbuf_discard),
	  __imm(bpf_throw),
	  [len]"i"(offsetof(struct __sk_buff, len))
	: __clobber_all);
}

/* bpf_throw() leaves a spin lock and a section too. */
SEC("tc")
int throw_spin_lock(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	mark_acquired(&glock);
	bpf_spin_lock(&glock);
	if (ctx->len)
		bpf_throw(0xeB9F);
	bpf_spin_unlock(&glock);
	bpf_obj_drop(f);
	return 0;
}

SEC("tc")
int throw_rcu(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	bpf_rcu_read_lock();
	if (ctx->len)
		bpf_throw(0xeB9F);
	bpf_rcu_read_unlock();
	bpf_obj_drop(f);
	return 0;
}

SEC("tc")
int throw_irq(struct __sk_buff *ctx)
{
	unsigned long flags;

	mark_acquired(&flags);
	bpf_local_irq_save(&flags);
	bpf_preempt_disable();
	if (ctx->len)
		bpf_throw(0xeB9F);
	bpf_preempt_enable();
	bpf_local_irq_restore(&flags);
	return 0;
}

/*
 * The record is read by nothing after its acquisition, and the register that
 * held it is overwritten: the program keeps the pointer nowhere at the throw,
 * and the record is released from the slot the acquisition filled.
 */
SEC("tc")
__naked int throw_dead_reg(void)
{
	asm volatile (
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 1f;"
	"r1 = %[acquired] ll;"
	"*(u64 *)(r1 + 0) = r0;"
	"r2 = 1;"
	"r1 = %[acquired_cnt] ll;"
	"*(u32 *)(r1 + 0) = r2;"
	"r0 = 0;"
	"r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"1: r0 = 0;"
	"exit;"
	:
	: __imm_addr(ringbuf),
	  __imm_addr(acquired),
	  __imm_addr(acquired_cnt),
	  __imm(bpf_ringbuf_reserve),
	  __imm(bpf_throw)
	: __clobber_all);
}

/* Two elements, so that a lock of one is found through the pointer to it, not at a fixed address. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct locked_foo);
	__uint(max_entries, 2);
} lock_map SEC(".maps");

/*
 * The lock of a map element is taken through the pointer in R7, which the
 * path holding a record then moves to R9, leaving a number in R7: no
 * register holds the pointer on both paths to the throw. The lock is
 * released from the slot of the frame, which holds the address of the lock
 * since the call that took it, and the record after the lock.
 */
SEC("tc")
__naked int throw_lock_two_locations(void)
{
	asm volatile (
	"r6 = *(u32 *)(r1 + %[len]);"
	"r1 = 0;"
	"*(u32 *)(r10 - 4) = r1;"
	"r1 = %[lock_map] ll;"
	"r2 = r10;"
	"r2 += -4;"
	"call %[bpf_map_lookup_elem];"
	"if r0 == 0 goto 3f;"
	"r7 = r0;"
	"r2 = r7;"
	"r2 += %[lock_off];"
	"r1 = %[acquired] ll;"
	"*(u64 *)(r1 + 0) = r2;"
	"r2 = 1;"
	"r1 = %[acquired_cnt] ll;"
	"*(u32 *)(r1 + 0) = r2;"
	"r8 = 0;"
	"if r6 == 0 goto 1f;"
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 3f;"
	"r8 = r0;"
	"r1 = %[acquired] ll;"
	"*(u64 *)(r1 + 8) = r0;"
	"r2 = 2;"
	"r1 = %[acquired_cnt] ll;"
	"*(u32 *)(r1 + 0) = r2;"
	"1: r1 = r7;"
	"r1 += %[lock_off];"
	"call %[bpf_spin_lock];"
	"r9 = 42;"
	"if r8 == 0 goto 2f;"
	"r9 = r7;"
	"r7 = 42;"
	"2: r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"3: r0 = 0;"
	"exit;"
	:
	: __imm_addr(lock_map),
	  __imm_addr(ringbuf),
	  __imm_addr(acquired),
	  __imm_addr(acquired_cnt),
	  __imm(bpf_map_lookup_elem),
	  __imm(bpf_ringbuf_reserve),
	  __imm(bpf_spin_lock),
	  __imm(bpf_throw),
	  [len]"i"(offsetof(struct __sk_buff, len)),
	  [lock_off]"i"(offsetof(struct locked_foo, lock))
	: __clobber_all);
}

/*
 * Two records, of which the one the test chooses is discarded at a single
 * instruction. The paths discarding either reach the throw with the other
 * record in its register and a dead pointer in the register of the discarded
 * one: the frame has a slot for each record, and the discard clears the slot
 * that holds the pointer it releases, whichever it is.
 */
SEC("tc")
__naked int throw_shared_release(void)
{
	asm volatile (
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 2f;"
	"r6 = r0;"
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 1f;"
	"r7 = r0;"
	"r1 = %[acquired] ll;"
	"*(u64 *)(r1 + 0) = r6;"
	"*(u64 *)(r1 + 8) = r7;"
	"r2 = 2;"
	"r1 = %[acquired_cnt] ll;"
	"*(u32 *)(r1 + 0) = r2;"
	"r8 = %[param] ll;"
	"r8 = *(u32 *)(r8 + 0);"
	"r1 = r6;"
	"if r8 == 0 goto +1;"
	"r1 = r7;"
	"r2 = 0;"
	"call %[bpf_ringbuf_discard];"
	"r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"1: r1 = r6;"
	"r2 = 0;"
	"call %[bpf_ringbuf_discard];"
	"2: r0 = 0;"
	"exit;"
	:
	: __imm_addr(ringbuf),
	  __imm_addr(acquired),
	  __imm_addr(acquired_cnt),
	  __imm_addr(param),
	  __imm(bpf_ringbuf_reserve),
	  __imm(bpf_ringbuf_discard),
	  __imm(bpf_throw)
	: __clobber_all);
}

struct refcounted_foo {
	int data;
	struct bpf_list_node node;
	struct bpf_refcount ref;
};

/*
 * Two references to one object, its allocation and a bpf_refcount_acquire()
 * of it, hold the same pointer, and the one the test chooses is dropped. Each
 * has a slot of the frame, and the two hold equal handles: the drop clears
 * one slot holding the pointer, whichever it is, and the unwinder drops the
 * object exactly once more.
 */
SEC("tc")
int throw_refcount_shared_release(struct __sk_buff *ctx)
{
	struct refcounted_foo *a, *b;

	a = bpf_obj_new(typeof(*a));
	if (!a)
		return 1;
	b = bpf_refcount_acquire(a);
	mark_acquired(a);
	bpf_obj_drop(param ? a : b);
	bpf_throw(0xeB9F);
	return 0;
}

/* The node first, so that the pointer to it is the pointer to the object. */
struct lfoo {
	struct bpf_list_node node;
	int data;
};

struct locked_list {
	struct bpf_spin_lock lock;
	struct bpf_list_head head __contains(lfoo, node);
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct locked_list);
	__uint(max_entries, 1);
} locked_list_map SEC(".maps");

/* Pops a node under its caller's lock, and throws holding it. */
static __noinline struct bpf_list_node *pop_and_throw(struct locked_list *l)
{
	struct bpf_list_node *n = bpf_list_pop_front(&l->head);

	if (n)
		mark_acquired(n);
	bpf_throw(0xeB9F);
	return n;
}

/*
 * The callee's node was popped under the lock its caller holds. Locks are
 * released before objects, whichever frame holds them: the unwinder unlocks
 * the caller's lock, then drops the node.
 */
SEC("tc")
int throw_obj_after_caller_lock(struct __sk_buff *ctx)
{
	struct bpf_list_node *n;
	struct locked_list *l;
	struct lfoo *f;
	int key = 0;

	l = bpf_map_lookup_elem(&locked_list_map, &key);
	if (!l)
		return 1;
	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(&l->lock);
	bpf_spin_lock(&l->lock);
	bpf_list_push_back(&l->head, &f->node);
	n = pop_and_throw(l);
	if (n)
		bpf_list_push_back(&l->head, n);
	bpf_spin_unlock(&l->lock);
	return 0;
}

/* Enters an RCU read section and throws in it. */
static __noinline int rcu_and_throw(void)
{
	bpf_rcu_read_lock();
	bpf_throw(0xeB9F);
	bpf_rcu_read_unlock();
	return 0;
}

/*
 * The destructor of a kmem_cache iterator sleeps, and the callee throws in an
 * RCU read section: sections are left before objects are released, whichever
 * frame holds them, so the iterator is destroyed outside the section. Only a
 * sleepable program may create it: a syscall program.
 */
SEC("syscall")
int throw_sleeping_dtor_after_section(void *ctx)
{
	struct bpf_iter_kmem_cache it;

	bpf_iter_kmem_cache_new(&it);
	mark_acquired(&it);
	rcu_and_throw();
	bpf_iter_kmem_cache_destroy(&it);
	return 0;
}

/*
 * Two paths save the same two sets of IRQ flags in opposite orders and meet at
 * the throw, kept apart by the RCU read section one of them holds: the
 * unwinder restores the flags saved with interrupts disabled first and the
 * ones saved with them enabled last, whichever path ran.
 */
SEC("tc")
int throw_irq_order(struct __sk_buff *ctx)
{
	int order = param;
	unsigned long a, b;

	mark_acquired(&a);
	mark_acquired(&b);
	if (order) {
		bpf_local_irq_save(&a);
		bpf_local_irq_save(&b);
		bpf_rcu_read_lock();
	} else {
		bpf_local_irq_save(&b);
		bpf_local_irq_save(&a);
	}
	if (ctx->len)
		bpf_throw(0xeB9F);
	if (order) {
		bpf_rcu_read_unlock();
		bpf_local_irq_restore(&b);
		bpf_local_irq_restore(&a);
	} else {
		bpf_local_irq_restore(&a);
		bpf_local_irq_restore(&b);
	}
	return 0;
}

/*
 * Allocates, recurses while holding, and throws in the innermost frame: every
 * frame of the subprog holds an object obtained at the same instruction, each
 * in the slot of its own frame.
 */
static __noinline int alloc_recurse_throw(int n)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 0;
	mark_acquired(f);
	if (n)
		alloc_recurse_throw(n - 1);
	else
		bpf_throw(0xeB9F);
	bpf_obj_drop(f);
	return 0;
}

SEC("tc")
int throw_recursion_holding(struct __sk_buff *ctx)
{
	return alloc_recurse_throw(3);
}

/* The object, in the stack of the frame that passes the struct to a callee. */
struct slot_ctx {
	struct foo *node;
};

/*
 * Stashes the caller's object, overwrites the stack slot it came from with a
 * number across the throw, and puts it back: the caller's stack holds no
 * pointer to the object at the throw.
 */
static __noinline void clobber_slot_and_throw(struct slot_ctx *c)
{
	struct foo *f = c->node;

	c->node = (void *)(long)param;
	bpf_throw(0xeB9F);
	c->node = f;
}

/*
 * The caller keeps the object in the stack slot alone at the call, which the
 * callee writes: the object is released from the hidden slot of the caller's
 * frame, once, whatever the stack slot holds.
 */
SEC("tc")
int throw_callee_clobbers_slot(struct __sk_buff *ctx)
{
	struct slot_ctx c;
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	c.node = f;
	clobber_slot_and_throw(&c);
	bpf_obj_drop(c.node);
	return 0;
}

/* ---- what the frames hold at call depth two ---- */

/*
 * Reserves a record of its own and discards it before the throw when told,
 * after it otherwise: its caller says so by a constant, and its frame holds
 * the record at the throw through one call and not through the other.
 */
__used static __noinline int reserve_and_throw(const long *flag, int drop)
{
	void *rec;

	rec = bpf_ringbuf_reserve(&ringbuf, 8, 0);
	if (!rec)
		return 1;
	mark_acquired(rec);
	if (drop)
		bpf_ringbuf_discard(rec, 0);
	if (*flag & 1)
		bpf_throw(0xeB9F);
	if (!drop)
		bpf_ringbuf_discard(rec, 0);
	return 0;
}

/* Two calls of reserve_and_throw() with a constant each, which clang would merge in C. */
__naked static __noinline int call_twice(const long *flag)
{
	asm volatile (
	"r6 = r1;"
	"r2 = *(u64 *)(r1 + 0);"
	"r2 &= 2;"
	"if r2 == 0 goto 1f;"
	"r1 = r6;"
	"r2 = 0;"
	"call reserve_and_throw;"
	"exit;"
	"1: r1 = r6;"
	"r2 = 1;"
	"call reserve_and_throw;"
	"exit;"
	:
	:
	: __clobber_all);
}

/*
 * The throw is at depth two, reached through either call of the frame below:
 * the slot of the frame that throws holds the record or is empty.
 */
SEC("tc")
int throw_ringbuf_depth2_split(struct __sk_buff *ctx)
{
	long flag = param;

	return call_twice(&flag);
}

/* ---- a throw reached by paths of different stack depth ---- */

/*
 * A throw reached first by a path that never wrote fp-16, then by one that
 * keeps the record only there: the record is in the hidden slot of the frame
 * on the second path, and the slot is empty on the first.
 */
SEC("tc")
__naked int throw_slot_unallocated(void)
{
	asm volatile (
	"r6 = %[param] ll;"
	"r6 = *(u32 *)(r6 + 0);"
	"if r6 == 0 goto 1f;"
	"2: r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"exit;"
	"1: r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 3f;"
	"*(u64 *)(r10 - 16) = r0;"
	"r1 = %[acquired] ll;"
	"*(u64 *)(r1 + 0) = r0;"
	"r2 = 1;"
	"r1 = %[acquired_cnt] ll;"
	"*(u32 *)(r1 + 0) = r2;"
	"r0 = 0;"
	"goto 2b;"
	"3: r0 = 0;"
	"exit;"
	:
	: __imm_addr(param),
	  __imm_addr(ringbuf),
	  __imm_addr(acquired),
	  __imm_addr(acquired_cnt),
	  __imm(bpf_ringbuf_reserve),
	  __imm(bpf_throw)
	: __clobber_all);
}

/* ---- a reference that may be NULL when a callee throws ---- */

static __noinline int throw_if_told(const long *flag)
{
	if (*flag & 1)
		bpf_throw(0xeB9F);
	return 0;
}

/*
 * A call that throws between the acquisition and the NULL check: a lookup
 * that returned NULL acquired nothing, and left the slot of the frame empty.
 */
SEC("tc")
int throw_task_maybe_null(struct __sk_buff *ctx)
{
	long flag = param;
	struct task_struct *t;

	t = bpf_task_from_pid(param & 2 ? test_pid : -1);
	mark_acquired(t);
	throw_if_told(&flag);
	if (!t)
		return 1;
	bpf_task_release(t);
	return 0;
}

/* ---- a reference held as a pointer into the object ---- */

private(D) struct bpf_spin_lock pop_lock;
private(D) struct bpf_list_head pop_head __contains(foo, node);

/* Pushes a fresh object into the list the pop below takes it from. */
__used static __noinline int push_one(void)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 0;
	mark_acquired(f);
	bpf_spin_lock(&pop_lock);
	bpf_list_push_front(&pop_head, &f->node);
	bpf_spin_unlock(&pop_lock);
	return 0;
}

/*
 * Pops a node, which points 8 bytes into its object, and keeps it in R6 on
 * one path and a number on the other: the slot of the frame holds the object
 * the node is in, which the throw releases. With param the list is empty and
 * the pop returns NULL, which leaves the slot empty.
 */
SEC("tc")
__naked int throw_pop_null(void)
{
	asm volatile (
	"r1 = %[param] ll;"
	"r1 = *(u32 *)(r1 + 0);"
	"if r1 != 0 goto 1f;"
	"call push_one;"
	"1: r1 = %[pop_lock] ll;"
	"call %[bpf_spin_lock];"
	"r1 = %[pop_head] ll;"
	"call %[bpf_list_pop_front];"
	"r6 = r0;"
	"r1 = %[pop_lock] ll;"
	"call %[bpf_spin_unlock];"
	"if r6 != 0 goto 2f;"
	"r6 = 42;"
	"2: r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"exit;"
	:
	: __imm_addr(param),
	  __imm_addr(pop_lock),
	  __imm_addr(pop_head),
	  __imm(bpf_spin_lock),
	  __imm(bpf_spin_unlock),
	  __imm(bpf_list_pop_front),
	  __imm(bpf_throw)
	: __clobber_all);
}

/*
 * The record is spilled around a helper the JIT inlines, a spill the verifier
 * removes again, and sits in R6 at the throw: the unwinder takes it from the
 * slot its frame keeps it in, not from the program's stack.
 */
SEC("tc")
__naked int throw_fastcall_spill(void)
{
	asm volatile (
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 2f;"
	"r1 = r0;"
	"*(u64 *)(r10 - 8) = r1;"
	"call %[bpf_get_smp_processor_id];"
	"r1 = *(u64 *)(r10 - 8);"
	"r6 = r1;"
	"r2 = %[acquired] ll;"
	"*(u64 *)(r2 + 0) = r6;"
	"r2 = %[acquired_cnt] ll;"
	"r3 = 1;"
	"*(u32 *)(r2 + 0) = r3;"
	"r2 = %[param] ll;"
	"r2 = *(u32 *)(r2 + 0);"
	"if r2 != 0 goto 1f;"
	"r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"1: r1 = r6;"
	"r2 = 0;"
	"call %[bpf_ringbuf_discard];"
	"2: r0 = 0;"
	"exit;"
	:
	: __imm_addr(ringbuf),
	  __imm_addr(acquired),
	  __imm_addr(acquired_cnt),
	  __imm_addr(param),
	  __imm(bpf_ringbuf_reserve),
	  __imm(bpf_ringbuf_discard),
	  __imm(bpf_get_smp_processor_id),
	  __imm(bpf_throw)
	: __clobber_all);
}

/* ---- a reference a subprog returns ---- */

static __noinline struct foo *alloc_foo(void)
{
	return bpf_obj_new(struct foo);
}

/*
 * The subprog returns the object it allocated: the call acquires it for the
 * caller, which holds it at the throw.
 */
SEC("tc")
int throw_obj_returned(struct __sk_buff *ctx)
{
	struct foo *f;

	f = alloc_foo();
	if (!f)
		return 1;
	mark_acquired(f);
	if (ctx->len)
		bpf_throw(0xeB9F);
	bpf_obj_drop(f);
	return 0;
}

/* ---- a call that releases on some paths only ---- */

struct foo_value {
	struct foo __kptr *f;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct foo_value);
} foo_map SEC(".maps");

/*
 * The object goes into the map when the test says so, and NULL otherwise: the
 * slot of the object is cleared when the call took the object, and still
 * holds it at the throw when the call took NULL.
 */
SEC("tc")
int throw_xchg_maybe(struct __sk_buff *ctx)
{
	struct foo_value *v;
	struct foo *f, *old;

	v = bpf_map_lookup_elem(&foo_map, &(int){0});
	if (!v)
		return 1;
	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	old = bpf_kptr_xchg(&v->f, param ? f : NULL);
	if (old)
		bpf_obj_drop(old);
	bpf_throw(0xeB9F);
	return 0;
}

/* ---- what the frames keep in their own stack at the throw ---- */

/*
 * The record is spilled when the throw is reached, on every path to it: the
 * unwinder takes it from the slot of the program's stack that the descriptor
 * of the throw names, and the frame keeps no slot for it.
 */
SEC("tc")
__naked int throw_spilled(void)
{
	asm volatile (
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 1f;"
	"*(u64 *)(r10 - 8) = r0;"
	"r1 = %[acquired] ll;"
	"*(u64 *)(r1 + 0) = r0;"
	"r2 = 1;"
	"r1 = %[acquired_cnt] ll;"
	"*(u32 *)(r1 + 0) = r2;"
	"r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"1: r0 = 0;"
	"exit;"
	:
	: __imm_addr(ringbuf),
	  __imm_addr(acquired),
	  __imm_addr(acquired_cnt),
	  __imm(bpf_ringbuf_reserve),
	  __imm(bpf_throw)
	: __clobber_all);
}

/* Throws when the test says so. */
__used static __noinline int throw_if_param(void)
{
	if (!param)
		bpf_throw(0xeB9F);
	return 0;
}

/*
 * The record is spilled in the caller of the subprog that throws: the
 * unwinder takes it from the caller's stack, where the descriptor of the
 * call says it is. When the callee returns the caller discards it.
 */
SEC("tc")
__naked int throw_spilled_caller(void)
{
	asm volatile (
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 1f;"
	"*(u64 *)(r10 - 8) = r0;"
	"r1 = %[acquired] ll;"
	"*(u64 *)(r1 + 0) = r0;"
	"r2 = 1;"
	"r1 = %[acquired_cnt] ll;"
	"*(u32 *)(r1 + 0) = r2;"
	"call throw_if_param;"
	"r1 = *(u64 *)(r10 - 8);"
	"r2 = 0;"
	"call %[bpf_ringbuf_discard];"
	"1: r0 = 0;"
	"exit;"
	:
	: __imm_addr(ringbuf),
	  __imm_addr(acquired),
	  __imm_addr(acquired_cnt),
	  __imm(bpf_ringbuf_reserve),
	  __imm(bpf_ringbuf_discard)
	: __clobber_all);
}

/*
 * The node that was popped is spilled, a pointer 8 bytes into its object or
 * NULL when the list was empty: the unwinder releases the object the spilled
 * pointer is in, and nothing when the slot holds NULL.
 */
SEC("tc")
__naked int throw_spilled_node(void)
{
	asm volatile (
	"r1 = %[param] ll;"
	"r1 = *(u32 *)(r1 + 0);"
	"if r1 != 0 goto 1f;"
	"call push_one;"
	"1: r1 = %[pop_lock] ll;"
	"call %[bpf_spin_lock];"
	"r1 = %[pop_head] ll;"
	"call %[bpf_list_pop_front];"
	"*(u64 *)(r10 - 8) = r0;"
	"r1 = %[pop_lock] ll;"
	"call %[bpf_spin_unlock];"
	"r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"exit;"
	:
	: __imm_addr(param),
	  __imm_addr(pop_lock),
	  __imm_addr(pop_head),
	  __imm(bpf_spin_lock),
	  __imm(bpf_spin_unlock),
	  __imm(bpf_list_pop_front),
	  __imm(bpf_throw)
	: __clobber_all);
}

/*
 * The record is spilled on one path to the throw and in R6 on the other, and
 * in no other register: the paths do not agree on where it is, so the frame
 * keeps it in a slot, and it is released once on either path.
 */
SEC("tc")
__naked int throw_spilled_some_paths(void)
{
	asm volatile (
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 2f;"
	"r6 = r0;"
	"r1 = %[acquired] ll;"
	"*(u64 *)(r1 + 0) = r0;"
	"r2 = 1;"
	"r1 = %[acquired_cnt] ll;"
	"*(u32 *)(r1 + 0) = r2;"
	"r0 = 0;"
	"r1 = %[param] ll;"
	"r1 = *(u32 *)(r1 + 0);"
	"if r1 == 0 goto 1f;"
	"*(u64 *)(r10 - 8) = r6;"
	"r6 = 0;"
	"1: r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"2: r0 = 0;"
	"exit;"
	:
	: __imm_addr(ringbuf),
	  __imm_addr(acquired),
	  __imm_addr(acquired_cnt),
	  __imm_addr(param),
	  __imm(bpf_ringbuf_reserve),
	  __imm(bpf_throw)
	: __clobber_all);
}

/* Leaves the RCU read section of its caller and throws. */
static __noinline int rcu_unlock_and_throw(void)
{
	bpf_rcu_read_unlock();
	bpf_throw(0xeB9F);
	return 0;
}

/*
 * The callee leaves the section its caller entered and throws: the caller is
 * in one section at the call, the callee in one less than it was called in,
 * and no section is left to leave.
 */
SEC("tc")
int throw_callee_left_rcu(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	mark_acquired(f);
	bpf_rcu_read_lock();
	rcu_unlock_and_throw();
	bpf_obj_drop(f);
	return 0;
}

/*
 * The section is entered on one path to the throw only: the frame counts its
 * sections in a slot, and the unwinder leaves as many as it counted.
 */
SEC("tc")
__naked int throw_rcu_some_paths(void)
{
	asm volatile (
	"r6 = %[param] ll;"
	"r6 = *(u32 *)(r6 + 0);"
	"if r6 == 0 goto 1f;"
	"call %[bpf_rcu_read_lock];"
	"1: r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"exit;"
	:
	: __imm_addr(param),
	  __imm(bpf_rcu_read_lock),
	  __imm(bpf_throw)
	: __clobber_all);
}

/* ---- what the frames keep in registers at the throw ---- */

/* Throws, and uses no register but R1. */
__used __naked static __noinline int throw_leaf(void)
{
	asm volatile (
	"r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"exit;"
	:
	: __imm(bpf_throw)
	: __clobber_all);
}

/*
 * Holds a record of its own in R7 and overwrites R6, which its prologue has
 * to save for its caller then, before it calls the subprog that throws.
 */
__used __naked static __noinline int throw_mid(void)
{
	asm volatile (
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 1f;"
	"r7 = r0;"
	"r1 = %[acquired] ll;"
	"*(u64 *)(r1 + 16) = r0;"
	"r2 = 3;"
	"r1 = %[acquired_cnt] ll;"
	"*(u32 *)(r1 + 0) = r2;"
	"r6 = 42;"
	"call throw_leaf;"
	"r1 = r7;"
	"r2 = 0;"
	"call %[bpf_ringbuf_discard];"
	"1: r0 = 0;"
	"exit;"
	:
	: __imm_addr(ringbuf),
	  __imm_addr(acquired),
	  __imm_addr(acquired_cnt),
	  __imm(bpf_ringbuf_reserve),
	  __imm(bpf_ringbuf_discard)
	: __clobber_all);
}

/*
 * Three records in registers only, two frames up from the throw. The main
 * program has one in R6, which its callee saves and overwrites, and one in
 * R8, which no frame touches. The callee has one in R7, which the frame that
 * throws does not save. The unwinder has the registers of the throw, and
 * those of each caller from where the frame it called saved them: the frame
 * that throws holds nothing, its caller's record goes first, then the two of
 * the main program in the order it acquired them.
 */
SEC("tc")
__naked int throw_regs_callers(void)
{
	asm volatile (
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 2f;"
	"r6 = r0;"
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 1f;"
	"r8 = r0;"
	"r1 = %[acquired] ll;"
	"*(u64 *)(r1 + 0) = r6;"
	"*(u64 *)(r1 + 8) = r8;"
	"r2 = 2;"
	"r1 = %[acquired_cnt] ll;"
	"*(u32 *)(r1 + 0) = r2;"
	"call throw_mid;"
	"r1 = r8;"
	"r2 = 0;"
	"call %[bpf_ringbuf_discard];"
	"1: r1 = r6;"
	"r2 = 0;"
	"call %[bpf_ringbuf_discard];"
	"2: r0 = 0;"
	"exit;"
	:
	: __imm_addr(ringbuf),
	  __imm_addr(acquired),
	  __imm_addr(acquired_cnt),
	  __imm(bpf_ringbuf_reserve),
	  __imm(bpf_ringbuf_discard)
	: __clobber_all);
}

/*
 * The record is in R3 only when the frame throws, a register no call
 * preserves: the unwinder has every register of the frame that throws.
 */
SEC("tc")
__naked int throw_reg_caller_saved(void)
{
	asm volatile (
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 1f;"
	"r3 = r0;"
	"r1 = %[acquired] ll;"
	"*(u64 *)(r1 + 0) = r0;"
	"r2 = 1;"
	"r1 = %[acquired_cnt] ll;"
	"*(u32 *)(r1 + 0) = r2;"
	"r0 = 0;"
	"r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"1: r0 = 0;"
	"exit;"
	:
	: __imm_addr(ringbuf),
	  __imm_addr(acquired),
	  __imm_addr(acquired_cnt),
	  __imm(bpf_ringbuf_reserve),
	  __imm(bpf_throw)
	: __clobber_all);
}

/*
 * The node that was popped is in R6 at the throw, a pointer 8 bytes into its
 * object or NULL when the list was empty: the unwinder releases the object
 * the register points into, and nothing when it holds NULL.
 */
SEC("tc")
__naked int throw_reg_node(void)
{
	asm volatile (
	"r1 = %[param] ll;"
	"r1 = *(u32 *)(r1 + 0);"
	"if r1 != 0 goto 1f;"
	"call push_one;"
	"1: r1 = %[pop_lock] ll;"
	"call %[bpf_spin_lock];"
	"r1 = %[pop_head] ll;"
	"call %[bpf_list_pop_front];"
	"r6 = r0;"
	"r1 = %[pop_lock] ll;"
	"call %[bpf_spin_unlock];"
	"r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"exit;"
	:
	: __imm_addr(param),
	  __imm_addr(pop_lock),
	  __imm_addr(pop_head),
	  __imm(bpf_spin_lock),
	  __imm(bpf_spin_unlock),
	  __imm(bpf_list_pop_front),
	  __imm(bpf_throw)
	: __clobber_all);
}

/* ---- a callee that releases what its caller holds ---- */

/* Discards the record of its caller. */
__used static __noinline int discard_in_callee(void *rec)
{
	bpf_ringbuf_discard(rec, 0);
	return 0;
}

/*
 * The callee discards the record its caller passes it. A throw in front of
 * the call finds the caller holding the record, in R6, and one after the call
 * finds it holding nothing: no slot keeps the record, so the call that hands
 * it to the callee has none to empty.
 */
SEC("tc")
__naked int throw_callee_releases(void)
{
	asm volatile (
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 3f;"
	"r6 = r0;"
	"r1 = %[acquired] ll;"
	"*(u64 *)(r1 + 0) = r0;"
	"r2 = 1;"
	"r1 = %[acquired_cnt] ll;"
	"*(u32 *)(r1 + 0) = r2;"
	"r0 = 0;"
	"r7 = %[param] ll;"
	"r7 = *(u32 *)(r7 + 0);"
	"if r7 != 1 goto 1f;"
	"r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"1: r1 = r6;"
	"call discard_in_callee;"
	"if r7 != 2 goto 2f;"
	"r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"2: r0 = 0;"
	"3: exit;"
	:
	: __imm_addr(ringbuf),
	  __imm_addr(acquired),
	  __imm_addr(acquired_cnt),
	  __imm_addr(param),
	  __imm(bpf_ringbuf_reserve),
	  __imm(bpf_throw)
	: __clobber_all);
}

/*
 * Keeps the record its caller hands it in R6, discards it, and throws in
 * front of the discard or after it when the low bits of the test's choice
 * say so.
 */
__used __naked static __noinline int consume_in_callee(void)
{
	asm volatile (
	"r6 = r1;"
	"r7 = %[param] ll;"
	"r7 = *(u32 *)(r7 + 0);"
	"r7 &= 7;"
	"if r7 != 1 goto 1f;"
	"r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"1: r1 = r6;"
	"r2 = 0;"
	"call %[bpf_ringbuf_discard];"
	"if r7 != 2 goto 2f;"
	"r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"2: r0 = 0;"
	"exit;"
	:
	: __imm_addr(param),
	  __imm(bpf_ringbuf_discard),
	  __imm(bpf_throw)
	: __clobber_all);
}

/*
 * The caller hands the record to the callee that discards it, and keeps no
 * copy. The record is the callee's from the call on: a throw of the callee in
 * front of the discard finds it in R6 of the callee, and one after the
 * discard finds nothing.
 */
SEC("tc")
__naked int throw_callee_consumes(void)
{
	asm volatile (
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 1f;"
	"r1 = %[acquired] ll;"
	"*(u64 *)(r1 + 0) = r0;"
	"r2 = 1;"
	"r1 = %[acquired_cnt] ll;"
	"*(u32 *)(r1 + 0) = r2;"
	"r1 = r0;"
	"r0 = 0;"
	"call consume_in_callee;"
	"1: r0 = 0;"
	"exit;"
	:
	: __imm_addr(ringbuf),
	  __imm_addr(acquired),
	  __imm_addr(acquired_cnt),
	  __imm(bpf_ringbuf_reserve)
	: __clobber_all);
}

/*
 * The record is in R6 on one path to the throw of the caller and in R9 on the
 * other, so the caller keeps it in a slot. The call that hands the record to
 * the callee empties the slot: a throw of the callee in front of its discard
 * releases the record once, from the callee, and one after it releases
 * nothing.
 */
SEC("tc")
__naked int throw_callee_consumes_from_slot(void)
{
	asm volatile (
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 4f;"
	"r6 = r0;"
	"r1 = %[acquired] ll;"
	"*(u64 *)(r1 + 0) = r0;"
	"r2 = 1;"
	"r1 = %[acquired_cnt] ll;"
	"*(u32 *)(r1 + 0) = r2;"
	"r0 = 0;"
	"r9 = 0;"
	"r8 = %[param] ll;"
	"r8 = *(u32 *)(r8 + 0);"
	"r7 = r8;"
	"r7 &= 8;"
	"if r7 == 0 goto 1f;"
	"r9 = r6;"
	"r6 = 0;"
	"1: r8 &= 7;"
	"if r8 != 3 goto 2f;"
	"r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"2: r1 = r6;"
	"if r1 != 0 goto 3f;"
	"r1 = r9;"
	"3: call consume_in_callee;"
	"4: r0 = 0;"
	"exit;"
	:
	: __imm_addr(ringbuf),
	  __imm_addr(acquired),
	  __imm_addr(acquired_cnt),
	  __imm_addr(param),
	  __imm(bpf_ringbuf_reserve),
	  __imm(bpf_throw)
	: __clobber_all);
}

/*
 * The same through the address of the callee, with the record in no register
 * at the throw of the caller: the insns in front of the callx empty the slot
 * of the caller, so a throw of the callee in front of its discard releases
 * the record once.
 */
SEC("tc")
__naked int throw_callx_consumes_from_slot(void)
{
	asm volatile (
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 2f;"
	"r6 = r0;"
	"r1 = %[acquired] ll;"
	"*(u64 *)(r1 + 0) = r0;"
	"r2 = 1;"
	"r1 = %[acquired_cnt] ll;"
	"*(u32 *)(r1 + 0) = r2;"
	"r0 = 0;"
	"r8 = %[param] ll;"
	"r8 = *(u32 *)(r8 + 0);"
	"if r8 != 3 goto 1f;"
	"r6 = 0;"
	"r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"1: r1 = r6;"
	"r2 = %[consume_in_callee] ll;"
	"callx r2;"
	"2: r0 = 0;"
	"exit;"
	:
	: __imm_addr(ringbuf),
	  __imm_addr(acquired),
	  __imm_addr(acquired_cnt),
	  __imm_addr(param),
	  __imm_addr(consume_in_callee),
	  __imm(bpf_ringbuf_reserve),
	  __imm(bpf_throw)
	: __clobber_all);
}

/*
 * Discards the record its caller hands it. When it throws instead the record
 * is in no register: the cookie has taken its place in R1.
 */
__used __naked static __noinline int consume_or_lose(void)
{
	asm volatile (
	"r2 = %[param] ll;"
	"r2 = *(u32 *)(r2 + 0);"
	"if r2 != 1 goto 1f;"
	"r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"1: r2 = 0;"
	"call %[bpf_ringbuf_discard];"
	"r0 = 0;"
	"exit;"
	:
	: __imm_addr(param),
	  __imm(bpf_ringbuf_discard),
	  __imm(bpf_throw)
	: __clobber_all);
}

/*
 * The callee that is handed the record has it nowhere when it throws, so it
 * keeps it in a slot of its own, which its entry fills from the argument.
 */
SEC("tc")
__naked int throw_callee_consumes_slot(void)
{
	asm volatile (
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 1f;"
	"r1 = %[acquired] ll;"
	"*(u64 *)(r1 + 0) = r0;"
	"r2 = 1;"
	"r1 = %[acquired_cnt] ll;"
	"*(u32 *)(r1 + 0) = r2;"
	"r1 = r0;"
	"r0 = 0;"
	"call consume_or_lose;"
	"1: r0 = 0;"
	"exit;"
	:
	: __imm_addr(ringbuf),
	  __imm_addr(acquired),
	  __imm_addr(acquired_cnt),
	  __imm(bpf_ringbuf_reserve)
	: __clobber_all);
}

/* Unlocks the lock of the element its caller locked. */
__used static __noinline int unlock_in_callee(struct locked_foo *foo)
{
	bpf_spin_unlock(&foo->lock);
	return 0;
}

/*
 * The lock of a map element is held at the first throw, where the frame has
 * the pointer to the element nowhere: the lock is in a slot of the caller,
 * which the callee that unlocks it cannot reach. The caller empties the slot
 * in front of the call, and the throw after the call finds nothing held.
 */
SEC("tc")
__naked int throw_callee_unlocks(void)
{
	asm volatile (
	"r1 = 0;"
	"*(u32 *)(r10 - 4) = r1;"
	"r1 = %[lock_map] ll;"
	"r2 = r10;"
	"r2 += -4;"
	"call %[bpf_map_lookup_elem];"
	"if r0 == 0 goto 2f;"
	"r6 = r0;"
	"r2 = r6;"
	"r2 += %[lock_off];"
	"r1 = %[acquired] ll;"
	"*(u64 *)(r1 + 0) = r2;"
	"r2 = 1;"
	"r1 = %[acquired_cnt] ll;"
	"*(u32 *)(r1 + 0) = r2;"
	"r1 = r6;"
	"r1 += %[lock_off];"
	"call %[bpf_spin_lock];"
	"r7 = %[param] ll;"
	"r7 = *(u32 *)(r7 + 0);"
	"if r7 != 1 goto 1f;"
	"r6 = 0;"
	"r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"1: r1 = r6;"
	"call unlock_in_callee;"
	"if r7 != 2 goto 2f;"
	"r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"2: r0 = 0;"
	"exit;"
	:
	: __imm_addr(lock_map),
	  __imm_addr(acquired),
	  __imm_addr(acquired_cnt),
	  __imm_addr(param),
	  __imm(bpf_map_lookup_elem),
	  __imm(bpf_spin_lock),
	  __imm(bpf_throw),
	  [lock_off]"i"(offsetof(struct locked_foo, lock))
	: __clobber_all);
}

/* ---- what a frame holds that another frame acquired ---- */

static __noinline void new_iter_in_caller(struct bpf_iter_num *it)
{
	bpf_iter_num_new(it, 0, 10);
}

/*
 * The callee creates the iterator in the stack of its caller, which holds it
 * from then on: the throw of the caller destroys it.
 */
SEC("tc")
int throw_iter_from_callee(struct __sk_buff *ctx)
{
	struct bpf_iter_num it;
	int *v;

	new_iter_in_caller(&it);
	mark_acquired(&it);
	while ((v = bpf_iter_num_next(&it))) {
		if (*v == 3 && ctx->len)
			bpf_throw(0xeB9F);
	}
	bpf_iter_num_destroy(&it);
	return 0;
}

static __noinline void enter_rcu_in_callee(void)
{
	bpf_rcu_read_lock();
}

/* The callee returns in the section it entered, which the throw of its caller leaves. */
SEC("tc")
int throw_rcu_from_callee(struct __sk_buff *ctx)
{
	enter_rcu_in_callee();
	if (ctx->len)
		bpf_throw(0xeB9F);
	bpf_rcu_read_unlock();
	return 0;
}

/* ---- locks the sites of a frame name ---- */

static __noinline void take_glock(void)
{
	bpf_spin_lock(&glock);
}

/*
 * A subprog takes the lock for its caller, which throws holding it: the lock
 * of a global variable is at a fixed address, which the throw unlocks.
 */
SEC("tc")
int throw_lock_from_callee(struct __sk_buff *ctx)
{
	mark_acquired(&glock);
	take_glock();
	if (ctx->len)
		bpf_throw(0xeB9F);
	bpf_spin_unlock(&glock);
	return 0;
}

/*
 * The lock of a map element is taken through the pointer in R7, which the
 * frame still has at the throw: the lock is found through it.
 */
SEC("tc")
__naked int throw_lock_in_value(void)
{
	asm volatile (
	"r1 = 0;"
	"*(u32 *)(r10 - 4) = r1;"
	"r1 = %[lock_map] ll;"
	"r2 = r10;"
	"r2 += -4;"
	"call %[bpf_map_lookup_elem];"
	"if r0 == 0 goto 1f;"
	"r7 = r0;"
	"r2 = r7;"
	"r2 += %[lock_off];"
	"r1 = %[acquired] ll;"
	"*(u64 *)(r1 + 0) = r2;"
	"r2 = 1;"
	"r1 = %[acquired_cnt] ll;"
	"*(u32 *)(r1 + 0) = r2;"
	"r1 = r7;"
	"r1 += %[lock_off];"
	"call %[bpf_spin_lock];"
	"r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"1: r0 = 0;"
	"exit;"
	:
	: __imm_addr(lock_map),
	  __imm_addr(acquired),
	  __imm_addr(acquired_cnt),
	  __imm(bpf_map_lookup_elem),
	  __imm(bpf_spin_lock),
	  __imm(bpf_throw),
	  [lock_off]"i"(offsetof(struct locked_foo, lock))
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
