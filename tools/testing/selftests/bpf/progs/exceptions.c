// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

#ifndef ETH_P_IP
#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#endif

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 4);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} jmp_table SEC(".maps");

SEC("tc")
int exception_throw(struct __sk_buff *ctx)
{
	volatile int ret = 1;

	if (ctx->protocol)
		throw;
	return ret;
}


static __noinline int subprog(struct __sk_buff *ctx)
{
	return ctx->len;
}

static __noinline int throwing_subprog(struct __sk_buff *ctx)
{
	volatile int ret = 0;

	if (ctx->protocol)
		throw;
	return ret;
}

__noinline int global_subprog(struct __sk_buff *ctx)
{
	return subprog(ctx) + 1;
}

__noinline int throwing_global_subprog(struct __sk_buff *ctx)
{
	volatile int ret = 0;

	if (ctx->protocol)
		throw;
	return ret;
}

__noinline int throwing_global_subprog_value(struct __sk_buff *ctx, u64 value)
{
	volatile int ret = 0;

	if (ctx->protocol)
		throw_value(value);
	return ret;
}

static __noinline int exception_cb(u64 c)
{
	volatile int ret = 16;

	return ret;
}

SEC("tc")
int exception_throw_subprog(struct __sk_buff *ctx)
{
	volatile int i;

	bpf_set_exception_callback(exception_cb);
	i = subprog(ctx);
	i += global_subprog(ctx) - 1;
	if (!i)
		return throwing_global_subprog(ctx);
	else
		return throwing_subprog(ctx);
	throw;
	return 0;
}

__noinline int throwing_gfunc(volatile int i)
{
	volatile int ret = 1;

	bpf_assert_eq(i, 0);
	return ret;
}

__noinline static int throwing_func(volatile int i)
{
	volatile int ret = 1;

	bpf_assert_lt(i, 1);
	return ret;
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

static int exception_cb_nz(u64 cookie)
{
	volatile int ret = 42;

	return ret;
}

SEC("tc")
int exception_tail_call_target(struct __sk_buff *ctx)
{
	bpf_set_exception_callback(exception_cb_nz);
	throw;
}

static __noinline
int exception_tail_call_subprog(struct __sk_buff *ctx)
{
	volatile int ret = 10;

	bpf_tail_call_static(ctx, &jmp_table, 0);
	return ret;
}

SEC("tc")
int exception_tail_call(struct __sk_buff *ctx) {
	volatile int ret = 0;

	bpf_set_exception_callback(exception_cb);
	ret = exception_tail_call_subprog(ctx);
	return ret + 8;
}

__noinline int exception_ext_global(struct __sk_buff *ctx)
{
	volatile int ret = 5;

	return ret;
}

static __noinline int exception_ext_static(struct __sk_buff *ctx)
{
	return exception_ext_global(ctx);
}

SEC("tc")
int exception_ext(struct __sk_buff *ctx)
{
	bpf_set_exception_callback(exception_cb_nz);
	return exception_ext_static(ctx);
}

static __noinline int exception_cb_value(u64 cookie)
{
	return cookie - 4;
}

SEC("tc")
int exception_throw_value(struct __sk_buff *ctx)
{
	bpf_set_exception_callback(exception_cb_value);
	return throwing_global_subprog_value(ctx, 64);
}

SEC("tc")
int exception_assert_eq(struct __sk_buff *ctx)
{
	bpf_set_exception_callback(exception_cb);
	bpf_assert_eq(ctx->protocol, IPPROTO_UDP);
	return 6;
}

SEC("tc")
int exception_assert_ne(struct __sk_buff *ctx)
{
	bpf_set_exception_callback(exception_cb);
	bpf_assert_ne(ctx->protocol, __bpf_htons(ETH_P_IP));
	return 6;
}

SEC("tc")
int exception_assert_lt(struct __sk_buff *ctx)
{
	bpf_set_exception_callback(exception_cb);
	bpf_assert_lt(ctx->protocol, __bpf_htons(ETH_P_IP) - 1);
	return 6;
}

SEC("tc")
int exception_assert_gt(struct __sk_buff *ctx)
{
	bpf_set_exception_callback(exception_cb);
	bpf_assert_gt(ctx->protocol, __bpf_htons(ETH_P_IP) + 1);
	return 6;
}

SEC("tc")
int exception_assert_le(struct __sk_buff *ctx)
{
	bpf_set_exception_callback(exception_cb);
	bpf_assert_le(ctx->protocol, __bpf_htons(ETH_P_IP) - 1);
	return 6;
}

SEC("tc")
int exception_assert_ge(struct __sk_buff *ctx)
{
	bpf_set_exception_callback(exception_cb);
	bpf_assert_ge(ctx->protocol, __bpf_htons(ETH_P_IP) + 1);
	return 6;
}

SEC("tc")
int exception_assert_eq_ok(struct __sk_buff *ctx)
{
	bpf_set_exception_callback(exception_cb);
	bpf_assert_eq(ctx->protocol, __bpf_htons(ETH_P_IP));
	return 6;
}

SEC("tc")
int exception_assert_ne_ok(struct __sk_buff *ctx)
{
	bpf_set_exception_callback(exception_cb);
	bpf_assert_ne(ctx->protocol, IPPROTO_UDP);
	return 6;
}

SEC("tc")
int exception_assert_lt_ok(struct __sk_buff *ctx)
{
	bpf_set_exception_callback(exception_cb);
	bpf_assert_lt(ctx->protocol, __bpf_htons(ETH_P_IP) + 1);
	return 6;
}

SEC("tc")
int exception_assert_gt_ok(struct __sk_buff *ctx)
{
	bpf_set_exception_callback(exception_cb);
	bpf_assert_gt(ctx->protocol, __bpf_htons(ETH_P_IP) - 1);
	return 6;
}

SEC("tc")
int exception_assert_le_ok(struct __sk_buff *ctx)
{
	bpf_set_exception_callback(exception_cb);
	bpf_assert_le(ctx->protocol, __bpf_htons(ETH_P_IP));
	return 6;
}

SEC("tc")
int exception_assert_ge_ok(struct __sk_buff *ctx)
{
	bpf_set_exception_callback(exception_cb);
	bpf_assert_ge(ctx->protocol, __bpf_htons(ETH_P_IP));
	return 6;
}

SEC("tc")
int exception_assert_eq_value(struct __sk_buff *ctx)
{
	bpf_set_exception_callback(exception_cb_value);
	bpf_assert_eq_value(ctx->protocol, IPPROTO_UDP, 46);
	return 5;
}

SEC("tc")
int exception_assert_ne_value(struct __sk_buff *ctx)
{
	bpf_set_exception_callback(exception_cb_value);
	bpf_assert_ne_value(ctx->protocol, __bpf_htons(ETH_P_IP), 46);
	return 5;
}

SEC("tc")
int exception_assert_lt_value(struct __sk_buff *ctx)
{
	bpf_set_exception_callback(exception_cb_value);
	bpf_assert_lt_value(ctx->protocol, __bpf_htons(ETH_P_IP) - 1, 46);
	return 5;
}

SEC("tc")
int exception_assert_gt_value(struct __sk_buff *ctx)
{
	bpf_set_exception_callback(exception_cb_value);
	bpf_assert_gt_value(ctx->protocol, __bpf_htons(ETH_P_IP) + 1, 46);
	return 5;
}

SEC("tc")
int exception_assert_le_value(struct __sk_buff *ctx)
{
	bpf_set_exception_callback(exception_cb_value);
	bpf_assert_le_value(ctx->protocol, __bpf_htons(ETH_P_IP) - 1, 46);
	return 5;
}

SEC("tc")
int exception_assert_ge_value(struct __sk_buff *ctx)
{
	bpf_set_exception_callback(exception_cb_value);
	bpf_assert_ge_value(ctx->protocol, __bpf_htons(ETH_P_IP) + 1, 46);
	return 5;
}

SEC("tc")
int exception_assert_eq_ok_value(struct __sk_buff *ctx)
{
	bpf_set_exception_callback(exception_cb_value);
	bpf_assert_eq_value(ctx->protocol, __bpf_htons(ETH_P_IP), 46);
	return 5;
}

SEC("tc")
int exception_assert_ne_ok_value(struct __sk_buff *ctx)
{
	bpf_set_exception_callback(exception_cb_value);
	bpf_assert_ne_value(ctx->protocol, IPPROTO_UDP, 46);
	return 5;
}

SEC("tc")
int exception_assert_lt_ok_value(struct __sk_buff *ctx)
{
	bpf_set_exception_callback(exception_cb_value);
	bpf_assert_lt_value(ctx->protocol, __bpf_htons(ETH_P_IP) + 1, 46);
	return 5;
}

SEC("tc")
int exception_assert_gt_ok_value(struct __sk_buff *ctx)
{
	bpf_set_exception_callback(exception_cb_value);
	bpf_assert_gt_value(ctx->protocol, __bpf_htons(ETH_P_IP) - 1, 46);
	return 5;
}

SEC("tc")
int exception_assert_le_ok_value(struct __sk_buff *ctx)
{
	bpf_set_exception_callback(exception_cb_value);
	bpf_assert_le_value(ctx->protocol, __bpf_htons(ETH_P_IP), 46);
	return 5;
}

SEC("tc")
int exception_assert_ge_ok_value(struct __sk_buff *ctx)
{
	bpf_set_exception_callback(exception_cb_value);
	bpf_assert_ge_value(ctx->protocol, __bpf_htons(ETH_P_IP), 46);
	return 5;
}

char _license[] SEC("license") = "GPL";
