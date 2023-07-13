// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "bpf_misc.h"
#include "bpf_experimental.h"

extern void bpf_rcu_read_lock(void) __ksym;

#define private(name) SEC(".bss." #name) __hidden __attribute__((aligned(8)))

struct foo {
	struct bpf_rb_node node;
};

private(A) struct bpf_spin_lock lock;
private(A) struct bpf_rb_root rbtree __contains(foo, node);

__noinline static int subprog_lock(struct __sk_buff *ctx)
{
	volatile int ret = 0;

	bpf_spin_lock(&lock);
	if (ctx->len)
		throw;
	return ret;
}

SEC("?tc")
__failure __msg("function calls are not allowed while holding a lock")
int reject_with_lock(void *ctx)
{
	bpf_spin_lock(&lock);
	throw;
}

SEC("?tc")
__failure __msg("function calls are not allowed while holding a lock")
int reject_subprog_with_lock(void *ctx)
{
	return subprog_lock(ctx);
}

SEC("?tc")
__failure __msg("bpf_rcu_read_unlock is missing")
int reject_with_rcu_read_lock(void *ctx)
{
	bpf_rcu_read_lock();
	throw;
}

__noinline static int throwing_subprog(struct __sk_buff *ctx)
{
	if (ctx->len)
		throw;
	return 0;
}

SEC("?tc")
__failure __msg("bpf_rcu_read_unlock is missing")
int reject_subprog_with_rcu_read_lock(void *ctx)
{
	bpf_rcu_read_lock();
	return throwing_subprog(ctx);
}

static bool rbless(struct bpf_rb_node *n1, const struct bpf_rb_node *n2)
{
	throw;
}

SEC("?tc")
__failure __msg("function calls are not allowed while holding a lock")
int reject_with_rbtree_add_throw(void *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 0;
	bpf_spin_lock(&lock);
	bpf_rbtree_add(&rbtree, &f->node, rbless);
	return 0;
}

SEC("?tc")
__failure __msg("Unreleased reference")
int reject_with_reference(void *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 0;
	throw;
}

__noinline static int subprog_ref(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 0;
	throw;
}

__noinline static int subprog_cb_ref(u32 i, void *ctx)
{
	throw;
}

SEC("?tc")
__failure __msg("Unreleased reference")
int reject_with_cb_reference(void *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 0;
	bpf_loop(5, subprog_cb_ref, NULL, 0);
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
__failure __msg("Unreleased reference")
int reject_with_subprog_reference(void *ctx)
{
	return subprog_ref(ctx) + 1;
}

static __noinline int throwing_exception_cb(u64 c)
{
	if (!c)
		throw;
	return c;
}

static __noinline int exception_cb1(u64 c)
{
	volatile int i = 0;

	bpf_assert_eq(i, 0);
	return i;
}

static __noinline int exception_cb2(u64 c)
{
	volatile int i = 0;

	bpf_assert_eq(i, 0);
	return i;
}

__noinline int throwing_exception_gfunc(struct __sk_buff *ctx)
{
	return throwing_exception_cb(ctx->protocol);
}

SEC("?tc")
__failure __msg("cannot be called from callback")
int reject_throwing_exception_cb_1(struct __sk_buff *ctx)
{
	bpf_set_exception_callback(throwing_exception_cb);
	return 0;
}

SEC("?tc")
__failure __msg("cannot call exception cb directly")
int reject_throwing_exception_cb_2(struct __sk_buff *ctx)
{
	throwing_exception_gfunc(ctx);
	bpf_set_exception_callback(throwing_exception_cb);
	return 0;
}

SEC("?tc")
__failure __msg("can only be called once to set exception callback")
int reject_throwing_exception_cb_3(struct __sk_buff *ctx)
{
	if (ctx->protocol)
		bpf_set_exception_callback(exception_cb1);
	else
		bpf_set_exception_callback(exception_cb2);
	throw;
}

__noinline int gfunc_set_exception_cb(u64 c)
{
	bpf_set_exception_callback(exception_cb1);
	return 0;
}

SEC("?tc")
__failure __msg("can only be called from main prog")
int reject_set_exception_cb_gfunc(struct __sk_buff *ctx)
{
	gfunc_set_exception_cb(0);
	return 0;
}

static __noinline int exception_cb_rec(u64 c)
{
	bpf_set_exception_callback(exception_cb_rec);
	return 0;
}

SEC("?tc")
__failure __msg("can only be called from main prog")
int reject_set_exception_cb_rec1(struct __sk_buff *ctx)
{
	bpf_set_exception_callback(exception_cb_rec);
	return 0;
}

static __noinline int exception_cb_rec2(u64 c);

static __noinline int exception_cb_rec1(u64 c)
{
	bpf_set_exception_callback(exception_cb_rec2);
	return 0;
}

static __noinline int exception_cb_rec2(u64 c)
{
	bpf_set_exception_callback(exception_cb_rec2);
	return 0;
}

SEC("?tc")
__failure __msg("can only be called from main prog")
int reject_set_exception_cb_rec2(struct __sk_buff *ctx)
{
	bpf_set_exception_callback(exception_cb_rec1);
	return 0;
}

static __noinline int exception_cb_rec3(u64 c)
{
	bpf_set_exception_callback(exception_cb1);
	return 0;
}

SEC("?tc")
__failure __msg("can only be called from main prog")
int reject_set_exception_cb_rec3(struct __sk_buff *ctx)
{
	bpf_set_exception_callback(exception_cb_rec3);
	return 0;
}

static __noinline int exception_cb_bad_ret(u64 c)
{
	return 4242;
}

SEC("?fentry/bpf_check")
__failure __msg("At program exit the register R0 has value")
int reject_set_exception_cb_bad_ret(void *ctx)
{
	bpf_set_exception_callback(exception_cb_bad_ret);
	return 0;
}

__noinline static int loop_cb1(u32 index, int *ctx)
{
	throw;
	return 0;
}

__noinline static int loop_cb2(u32 index, int *ctx)
{
	throw;
	return 0;
}

SEC("?tc")
__failure __msg("cannot be called from callback")
int reject_exception_throw_cb(struct __sk_buff *ctx)
{
	volatile int ret = 1;

	bpf_loop(5, loop_cb1, NULL, 0);
	return ret;
}

SEC("?tc")
__failure __msg("cannot be called from callback")
int exception_throw_cb_diff(struct __sk_buff *ctx)
{
	volatile int ret = 1;

	if (ctx->protocol)
		bpf_loop(5, loop_cb1, NULL, 0);
	else
		bpf_loop(5, loop_cb2, NULL, 0);
	return ret;
}

char _license[] SEC("license") = "GPL";
