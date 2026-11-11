// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "bpf_misc.h"
#include "bpf_experimental.h"

extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;
extern void bpf_preempt_disable(void) __ksym;
extern void bpf_preempt_enable(void) __ksym;
extern void bpf_local_irq_save(unsigned long *) __ksym;
extern void bpf_local_irq_restore(unsigned long *) __ksym;

#define private(name) SEC(".bss." #name) __hidden __attribute__((aligned(8)))

struct foo {
	struct bpf_rb_node node;
};

struct hmap_elem {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, int);
	__type(value, struct hmap_elem);
} hmap SEC(".maps");

private(A) struct bpf_spin_lock lock;
private(A) struct bpf_rb_root rbtree __contains(foo, node);

__noinline void *exception_cb_bad_ret_type1(u64 cookie)
{
	return NULL;
}

__noinline void exception_cb_bad_ret_type2(u64 cookie)
{
}

__noinline int exception_cb_bad_arg_0(void)
{
	return 0;
}

__noinline int exception_cb_bad_arg_2(int a, int b)
{
	return 0;
}

__noinline int exception_cb_ok_arg_small(int a)
{
	return 0;
}

SEC("?tc")
__exception_cb(exception_cb_bad_ret_type1)
__failure __msg("Only void, scalar, arena pointer, or a struct/union of scalars and arena pointers up to 16 bytes is supported.")
int reject_exception_cb_type_1(struct __sk_buff *ctx)
{
	bpf_throw(0);
	return 0;
}

SEC("?tc")
__exception_cb(exception_cb_bad_arg_0)
__failure __msg("exception cb only supports single integer argument")
int reject_exception_cb_type_2(struct __sk_buff *ctx)
{
	bpf_throw(0);
	return 0;
}

SEC("?tc")
__exception_cb(exception_cb_bad_arg_2)
__failure __msg("exception cb only supports single integer argument")
int reject_exception_cb_type_3(struct __sk_buff *ctx)
{
	bpf_throw(0);
	return 0;
}

SEC("?tc")
__exception_cb(exception_cb_ok_arg_small)
__success
int reject_exception_cb_type_4(struct __sk_buff *ctx)
{
	bpf_throw(0);
	return 0;
}

SEC("?tc")
__exception_cb(exception_cb_bad_ret_type2)
__failure __msg("exception cb cannot return void")
int reject_exception_cb_type_5(struct __sk_buff *ctx)
{
	bpf_throw(0);
	return 0;
}

__noinline
static int timer_cb(void *map, int *key, struct bpf_timer *timer)
{
	bpf_throw(0);
	return 0;
}

SEC("?tc")
__failure __msg("cannot be called from callback subprog")
int reject_async_callback_throw(struct __sk_buff *ctx)
{
	struct hmap_elem *elem;

	elem = bpf_map_lookup_elem(&hmap, &(int){0});
	if (!elem)
		return 0;
	return bpf_timer_set_callback(&elem->timer, timer_cb);
}

__noinline static int subprog_lock(struct __sk_buff *ctx)
{
	volatile int ret = 0;

	bpf_spin_lock(&lock);
	if (ctx->len)
		bpf_throw(0);
	return ret;
}

SEC("?tc")
__arch_s390x
__failure __msg("function calls are not allowed while holding a lock")
int reject_with_lock(void *ctx)
{
	bpf_spin_lock(&lock);
	bpf_throw(0);
	return 0;
}

SEC("?tc")
__arch_s390x
__failure __msg("function calls are not allowed while holding a lock")
int reject_subprog_with_lock(void *ctx)
{
	return subprog_lock(ctx);
}

SEC("?tc")
__arch_s390x
__failure __msg("bpf_throw cannot be used inside bpf_rcu_read_lock-ed region")
int reject_with_rcu_read_lock(void *ctx)
{
	bpf_rcu_read_lock();
	bpf_throw(0);
	return 0;
}

__noinline static int throwing_subprog(struct __sk_buff *ctx)
{
	if (ctx->len)
		bpf_throw(0);
	return 0;
}

SEC("?tc")
__arch_s390x
__failure __msg("bpf_throw cannot be used inside bpf_rcu_read_lock-ed region")
int reject_subprog_with_rcu_read_lock(void *ctx)
{
	bpf_rcu_read_lock();
	throwing_subprog(ctx);
	bpf_rcu_read_unlock();
	return 0;
}

static bool rbless(struct bpf_rb_node *n1, const struct bpf_rb_node *n2)
{
	bpf_throw(0);
	return true;
}

SEC("?tc")
__arch_x86_64 __arch_arm64
__failure __msg("cannot be called from callback subprog")
int reject_with_rbtree_add_throw(void *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 0;
	bpf_spin_lock(&lock);
	bpf_rbtree_add(&rbtree, &f->node, rbless);
	bpf_spin_unlock(&lock);
	return 0;
}

SEC("?tc")
__arch_s390x
__failure __msg("Unreleased reference")
int reject_with_reference(void *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 0;
	bpf_throw(0);
	return 0;
}

__noinline int global_subprog_may_throw(struct __sk_buff *ctx)
{
	if (ctx->len)
		bpf_throw(0);
	return 0;
}

SEC("?tc")
__arch_s390x
__failure __msg("Unreleased reference")
int reject_global_subprog_throw_with_reference(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 0;
	if (ctx->protocol)
		global_subprog_may_throw(ctx);
	bpf_obj_drop(f);
	return 0;
}

__noinline static int subprog_ref(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 0;
	bpf_throw(0);
	return 0;
}

__noinline static int subprog_cb_ref(u32 i, void *ctx)
{
	bpf_throw(0);
	return 0;
}

SEC("?tc")
__arch_x86_64 __arch_arm64
__failure __msg("cannot be called from callback subprog")
int reject_with_cb_reference(void *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 0;
	bpf_loop(5, subprog_cb_ref, NULL, 0);
	bpf_obj_drop(f);
	return 0;
}

SEC("?tc")
__failure __msg("cannot be called from callback")
int reject_with_cb(void *ctx)
{
	bpf_loop(5, subprog_cb_ref, NULL, 0);
	return 0;
}

SEC("?tc")
__arch_s390x
__failure __msg("Unreleased reference")
int reject_with_subprog_reference(void *ctx)
{
	return subprog_ref(ctx) + 1;
}

__noinline int throwing_exception_cb(u64 c)
{
	bpf_throw(0);
	return c;
}

__noinline int exception_cb1(u64 c)
{
	return c;
}

__noinline int exception_cb2(u64 c)
{
	return c;
}

static __noinline int static_func(struct __sk_buff *ctx)
{
	return exception_cb1(ctx->tstamp);
}

__noinline int global_func(struct __sk_buff *ctx)
{
	return exception_cb1(ctx->tstamp);
}

SEC("?tc")
__exception_cb(throwing_exception_cb)
__failure __msg("cannot be called from callback subprog")
int reject_throwing_exception_cb(struct __sk_buff *ctx)
{
	return 0;
}

SEC("?tc")
__exception_cb(exception_cb1)
__failure __msg("cannot call exception cb directly")
int reject_exception_cb_call_global_func(struct __sk_buff *ctx)
{
	return global_func(ctx);
}

SEC("?tc")
__exception_cb(exception_cb1)
__failure __msg("cannot call exception cb directly")
int reject_exception_cb_call_static_func(struct __sk_buff *ctx)
{
	return static_func(ctx);
}

SEC("?tc")
__exception_cb(exception_cb1)
__exception_cb(exception_cb2)
__failure __msg("multiple exception callback tags for main subprog")
int reject_multiple_exception_cb(struct __sk_buff *ctx)
{
	bpf_throw(0);
	return 16;
}

__noinline int exception_cb_bad_ret(u64 c)
{
	return c;
}

SEC("?fentry/bpf_check")
__exception_cb(exception_cb_bad_ret)
__failure __msg("At program exit the register R0 has unknown scalar value should")
int reject_set_exception_cb_bad_ret1(void *ctx)
{
	return 0;
}

SEC("?fentry/bpf_check")
__failure __msg("At program exit the register R1 has smin=64 smax=64 should")
int reject_set_exception_cb_bad_ret2(void *ctx)
{
	bpf_throw(64);
	return 0;
}

__noinline static int loop_cb1(u32 index, int *ctx)
{
	bpf_throw(0);
	return 0;
}

__noinline static int loop_cb2(u32 index, int *ctx)
{
	bpf_throw(0);
	return 0;
}

SEC("?tc")
__failure __msg("cannot be called from callback")
int reject_exception_throw_cb(struct __sk_buff *ctx)
{
	bpf_loop(5, loop_cb1, NULL, 0);
	return 0;
}

SEC("?tc")
__failure __msg("cannot be called from callback")
int reject_exception_throw_cb_diff(struct __sk_buff *ctx)
{
	if (ctx->protocol)
		bpf_loop(5, loop_cb1, NULL, 0);
	else
		bpf_loop(5, loop_cb2, NULL, 0);
	return 0;
}

__weak
void foo(void)
{
	bpf_throw(1);
}

SEC("?fentry/bpf_check")
__failure __msg("At program exit the register R1 has smin=1 smax=1 should")
int reject_out_of_range_global_throw(struct __sk_buff *skb)
{
	foo();

	return 0;
}

__noinline static int always_throws(void)
{
	bpf_throw(0);
	return 0;
}

__noinline static int rcu_lock_then_throw(void)
{
	bpf_rcu_read_lock();
	bpf_throw(0);
	return 0;
}

SEC("?tc")
__arch_s390x
__failure __msg("bpf_throw cannot be used inside bpf_rcu_read_lock-ed region")
int reject_subprog_rcu_lock_throw(void *ctx)
{
	rcu_lock_then_throw();
	return 0;
}

SEC("?tc")
__arch_s390x
__failure __msg("bpf_throw cannot be used inside bpf_preempt_disable-ed region")
int reject_subprog_throw_preempt_lock(void *ctx)
{
	bpf_preempt_disable();
	always_throws();
	bpf_preempt_enable();
	return 0;
}

SEC("?tc")
__arch_s390x
__failure __msg("bpf_throw cannot be used inside bpf_local_irq_save-ed region")
int reject_subprog_throw_irq_lock(void *ctx)
{
	unsigned long flags;

	bpf_local_irq_save(&flags);
	always_throws();
	bpf_local_irq_restore(&flags);
	return 0;
}

/*
 * What a program that throws may not do yet: the frames keep what they hold
 * in hidden slots of their own, see kernel/bpf/frame_desc.c.
 */

struct locked_obj {
	struct bpf_spin_lock lock;
	int data;
};

private(L) struct bpf_spin_lock held_lock;

static __noinline void throw_around_unlock_held(int before, int after)
{
	if (before)
		bpf_throw(0);
	bpf_spin_unlock(&held_lock);
	if (after)
		bpf_throw(0);
}

/*
 * The callee may throw with the lock of its caller held and after it dropped
 * it, so the call of the caller says neither. The lock is in a slot of the
 * caller then, which the callee cannot reach to empty.
 */
SEC("?tc")
__arch_x86_64 __arch_arm64
__failure __msg("releases what another frame holds in a hidden slot")
int reject_callee_releases(struct __sk_buff *ctx)
{
	bpf_spin_lock(&held_lock);
	throw_around_unlock_held(ctx->len, ctx->mark);
	return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} fail_ringbuf SEC(".maps");

/* Discards the record when told. */
__used static __noinline int discard_if(void *rec, int drop)
{
	if (drop)
		bpf_ringbuf_discard(rec, 0);
	return 0;
}

/*
 * The two paths to the throw keep the record in different registers, so it is
 * in a slot, which the caller empties for the callee it hands the record to.
 * The callee returns holding the record when it is not told to discard it.
 */
SEC("?tc")
__arch_x86_64 __arch_arm64
__failure __msg("releases it on some paths only")
__naked int reject_callee_releases_sometimes(void)
{
	asm volatile (
	"r7 = *(u32 *)(r1 + %[len]);"
	"r8 = *(u32 *)(r1 + %[mark]);"
	"r2 = *(u32 *)(r1 + %[priority]);"
	"*(u64 *)(r10 - 8) = r2;"
	"r1 = %[fail_ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 4f;"
	"r6 = r0;"
	"r9 = 0;"
	"r0 = 0;"
	"if r7 == 0 goto 1f;"
	"r9 = r6;"
	"r6 = 0;"
	"1: r1 = *(u64 *)(r10 - 8);"
	"if r1 == 0 goto 2f;"
	"r1 = 0;"
	"call %[bpf_throw];"
	"2: r1 = r6;"
	"if r1 != 0 goto 3f;"
	"r1 = r9;"
	"3: r2 = r8;"
	"call discard_if;"
	"if r8 != 0 goto 4f;"
	"r1 = r6;"
	"if r1 != 0 goto +1;"
	"r1 = r9;"
	"r2 = 0;"
	"call %[bpf_ringbuf_discard];"
	"4: r0 = 0;"
	"exit;"
	:
	: __imm_addr(fail_ringbuf),
	  __imm(bpf_ringbuf_reserve),
	  __imm(bpf_ringbuf_discard),
	  __imm(bpf_throw),
	  [len]"i"(offsetof(struct __sk_buff, len)),
	  [mark]"i"(offsetof(struct __sk_buff, mark)),
	  [priority]"i"(offsetof(struct __sk_buff, priority))
	: __clobber_all);
}

__used static __noinline void leave_rcu(void)
{
	bpf_rcu_read_unlock();
}

/*
 * The paths to the throw are in an RCU read section or not, so the frame
 * counts its sections in a slot. The count does not follow what a callee
 * does: the callee leaves the section it was called in.
 */
SEC("?tc")
__arch_x86_64 __arch_arm64
__failure __msg("a subprog returns in other sections than it was called in")
__naked int reject_callee_leaves_rcu(void)
{
	asm volatile (
	"r6 = *(u32 *)(r1 + %[len]);"
	"r7 = *(u32 *)(r1 + %[mark]);"
	"if r6 == 0 goto 1f;"
	"call %[bpf_rcu_read_lock];"
	"1: if r7 == 0 goto 2f;"
	"r1 = 0;"
	"call %[bpf_throw];"
	"2: if r6 != 0 goto 3f;"
	"call %[bpf_rcu_read_lock];"
	"3: call leave_rcu;"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_rcu_read_lock),
	  __imm(bpf_throw),
	  [len]"i"(offsetof(struct __sk_buff, len)),
	  [mark]"i"(offsetof(struct __sk_buff, mark))
	: __clobber_all);
}

struct obj_map_value {
	struct locked_obj __kptr *obj;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct obj_map_value);
} obj_map SEC(".maps");

/* The unwinder would unlock a lock in an object that may be freed by then. */
SEC("?tc")
__arch_x86_64 __arch_arm64
__failure __msg("releases an object whose lock is held")
int reject_release_locked_obj(struct __sk_buff *ctx)
{
	struct obj_map_value *v;
	struct locked_obj *o;

	v = bpf_map_lookup_elem(&obj_map, &(int){0});
	if (!v)
		return 0;
	o = bpf_obj_new(typeof(*o));
	if (!o)
		return 0;
	bpf_spin_lock(&o->lock);
	o = bpf_kptr_xchg(&v->obj, o);
	bpf_throw(0);
	return 0;
}

/* The unwinder restores what is at the address of the flags. */
SEC("?tc")
__arch_x86_64 __arch_arm64
__failure __msg("cannot write over saved irq flags in a program that throws")
int reject_write_over_irq_flags(struct __sk_buff *ctx)
{
	unsigned long flags;

	bpf_local_irq_save(&flags);
	*(volatile unsigned long *)&flags = 0;
	bpf_throw(0);
	return 0;
}

/* The unwinder destroys what is at the address of the iterator. */
SEC("?tc")
__arch_x86_64 __arch_arm64
__failure __msg("cannot write over an iterator in a program that throws")
int reject_write_over_iter(struct __sk_buff *ctx)
{
	struct bpf_iter_num it;

	bpf_iter_num_new(&it, 0, 10);
	*(volatile __u64 *)&it = 0x1234;
	bpf_throw(0);
	return 0;
}

/* Nothing may destroy the iterator once the section it is protected by ended. */
SEC("?syscall")
__arch_x86_64 __arch_arm64
__failure __msg("an RCU protected iterator may not outlive its section in a program that throws")
int reject_rcu_iter_outlives_section(void *ctx)
{
	struct bpf_iter_task it;

	bpf_rcu_read_lock();
	bpf_iter_task_new(&it, NULL, BPF_TASK_ITER_ALL_PROCS);
	bpf_rcu_read_unlock();
	bpf_throw(0);
	return 0;
}

char _license[] SEC("license") = "GPL";
