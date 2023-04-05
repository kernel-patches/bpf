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
	bpf_spin_lock(&lock);
	if (ctx->len)
		bpf_throw();
	return 0;
}

SEC("?tc")
__failure __msg("function calls are not allowed while holding a lock")
int reject_with_lock(void *ctx)
{
	bpf_spin_lock(&lock);
	bpf_throw();
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
	bpf_throw();
}

__noinline static int throwing_subprog(struct __sk_buff *ctx)
{
	if (ctx->len)
		bpf_throw();
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
	bpf_throw();
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
	bpf_throw();
}

__noinline static int subprog_ref(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 0;
	bpf_throw();
}

__noinline static int subprog_cb_ref(u32 i, void *ctx)
{
	bpf_throw();
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
__failure __msg("Unreleased reference")
int reject_with_subprog_reference(void *ctx)
{
	return subprog_ref(ctx) + 1;
}

static __noinline int throwing_exception_cb(void)
{
	int i = 0;

	bpf_assert_ne(i, 0);
	return i;
}

static __noinline int exception_cb1(void)
{
	int i = 0;

	bpf_assert_eq(i, 0);
	return i;
}

static __noinline int exception_cb2(void)
{
	int i = 0;

	bpf_assert_eq(i, 0);
	return i;
}

__noinline int throwing_exception_gfunc(void)
{
	return throwing_exception_cb();
}

SEC("?tc")
__failure __msg("is used as exception callback, cannot throw")
int reject_throwing_exception_cb_1(struct __sk_buff *ctx)
{
	bpf_set_exception_callback(throwing_exception_cb);
	return 0;
}

SEC("?tc")
__failure __msg("exception callback can throw, which is not allowed")
int reject_throwing_exception_cb_2(struct __sk_buff *ctx)
{
	throwing_exception_gfunc();
	bpf_set_exception_callback(throwing_exception_cb);
	return 0;
}

SEC("?tc")
__failure __msg("different exception callback subprogs for same insn 7: 2 and 1")
int reject_throwing_exception_cb_3(struct __sk_buff *ctx)
{
	if (ctx->protocol)
		bpf_set_exception_callback(exception_cb1);
	else
		bpf_set_exception_callback(exception_cb2);
	bpf_throw();
}

__noinline int gfunc_set_exception_cb(void)
{
	bpf_set_exception_callback(exception_cb1);
	return 0;
}

SEC("?tc")
__failure __msg("exception callback cannot be set within global function or extension program")
int reject_set_exception_cb_gfunc(struct __sk_buff *ctx)
{
	gfunc_set_exception_cb();
	return 0;
}

static __noinline int exception_cb_rec(void)
{
	bpf_set_exception_callback(exception_cb_rec);
	return 0;
}

SEC("?tc")
__failure __msg("exception callback cannot be set from within exception callback")
int reject_set_exception_cb_rec1(struct __sk_buff *ctx)
{
	bpf_set_exception_callback(exception_cb_rec);
	return 0;
}

static __noinline int exception_cb_rec2(void);

static __noinline int exception_cb_rec1(void)
{
	bpf_set_exception_callback(exception_cb_rec2);
	return 0;
}

static __noinline int exception_cb_rec2(void)
{
	bpf_set_exception_callback(exception_cb_rec2);
	return 0;
}

SEC("?tc")
__failure __msg("exception callback cannot be set from within exception callback")
int reject_set_exception_cb_rec2(struct __sk_buff *ctx)
{
	bpf_set_exception_callback(exception_cb_rec1);
	return 0;
}

static __noinline int exception_cb_rec3(void)
{
	bpf_set_exception_callback(exception_cb1);
	return 0;
}

SEC("?tc")
__failure __msg("exception callback cannot be set from within exception callback")
int reject_set_exception_cb_rec3(struct __sk_buff *ctx)
{
	bpf_set_exception_callback(exception_cb_rec3);
	return 0;
}

static __noinline int exception_cb_bad_ret(void)
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

char _license[] SEC("license") = "GPL";
