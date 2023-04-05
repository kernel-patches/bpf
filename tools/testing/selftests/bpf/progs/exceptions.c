// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

SEC("tc")
int exception_throw(struct __sk_buff *ctx)
{
	if (ctx->data)
		bpf_throw();
	return 1;
}


static __noinline int subprog(struct __sk_buff *ctx)
{
	return ctx->len;
}

static __noinline int throwing_subprog(struct __sk_buff *ctx)
{
	if (ctx)
		bpf_throw();
	return 0;
}

__noinline int global_subprog(struct __sk_buff *ctx)
{
	return subprog(ctx) + 1;
}

__noinline int throwing_global_subprog(struct __sk_buff *ctx)
{
	if (ctx)
		bpf_throw();
	return 0;
}

static __noinline int exception_cb(void)
{
	return 16;
}

SEC("tc")
int exception_throw_subprog(struct __sk_buff *ctx)
{
	volatile int i;

	exception_cb();
	bpf_set_exception_callback(exception_cb);
	i = subprog(ctx);
	i += global_subprog(ctx) - 1;
	if (!i)
		return throwing_global_subprog(ctx);
	else
		return throwing_subprog(ctx);
	bpf_throw();
	return 0;
}

__noinline int throwing_gfunc(volatile int i)
{
	bpf_assert_eq(i, 0);
	return 1;
}

__noinline static int throwing_func(volatile int i)
{
	bpf_assert_lt(i, 1);
	return 1;
}

SEC("tc")
int exception_throw_gfunc1(void *ctx)
{
	return throwing_gfunc(0);
}

SEC("tc")
__noinline int exception_throw_gfunc2()
{
	return throwing_gfunc(1);
}

__noinline int throwing_gfunc_2(volatile int i)
{
	return throwing_gfunc(i);
}

SEC("tc")
int exception_throw_gfunc3(void *ctx)
{
	return throwing_gfunc_2(0);
}

SEC("tc")
int exception_throw_gfunc4(void *ctx)
{
	return throwing_gfunc_2(1);
}

SEC("tc")
int exception_throw_gfunc5(void *ctx)
{
	bpf_set_exception_callback(exception_cb);
	return throwing_gfunc_2(0);
}

SEC("tc")
int exception_throw_gfunc6(void *ctx)
{
	bpf_set_exception_callback(exception_cb);
	return throwing_gfunc_2(1);
}


SEC("tc")
int exception_throw_func1(void *ctx)
{
	return throwing_func(0);
}

SEC("tc")
int exception_throw_func2(void *ctx)
{
	return throwing_func(1);
}

__noinline static int throwing_func_2(volatile int i)
{
	return throwing_func(i);
}

SEC("tc")
int exception_throw_func3(void *ctx)
{
	return throwing_func_2(0);
}

SEC("tc")
int exception_throw_func4(void *ctx)
{
	return throwing_func_2(1);
}

SEC("tc")
int exception_throw_func5(void *ctx)
{
	bpf_set_exception_callback(exception_cb);
	return throwing_func_2(0);
}

SEC("tc")
int exception_throw_func6(void *ctx)
{
	bpf_set_exception_callback(exception_cb);
	return throwing_func_2(1);
}

__noinline static int loop_cb1(u32 index, int *ctx)
{
	bpf_throw();
	return 0;
}

__noinline static int loop_cb2(u32 index, int *ctx)
{
	bpf_throw();
	return 0;
}

SEC("tc")
int exception_throw_cb1(struct __sk_buff *ctx)
{
	bpf_loop(5, loop_cb1, NULL, 0);
	return 1;
}

SEC("tc")
int exception_throw_cb2(struct __sk_buff *ctx)
{
	bpf_set_exception_callback(exception_cb);
	bpf_loop(5, loop_cb1, NULL, 0);
	return 0;
}

SEC("tc")
int exception_throw_cb_diff(struct __sk_buff *ctx)
{
	bpf_set_exception_callback(exception_cb);
	if (ctx->protocol)
		bpf_loop(5, loop_cb1, NULL, 0);
	else
		bpf_loop(5, loop_cb2, NULL, 0);
	return 1;
}

extern void bpf_kfunc_call_test_always_throws(void) __ksym;
extern void bpf_kfunc_call_test_never_throws(void) __ksym;

SEC("tc")
int exception_throw_kfunc1(struct __sk_buff *ctx)
{
	bpf_kfunc_call_test_always_throws();
	return 1;
}

SEC("tc")
int exception_throw_kfunc2(struct __sk_buff *ctx)
{
	bpf_kfunc_call_test_never_throws();
	return 1;
}

char _license[] SEC("license") = "GPL";
