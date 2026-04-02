// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>

#define CLOCK_MONOTONIC 1

long a, b, c, d, e, f, g, i;

struct timer_elem {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct timer_elem);
} timer_map SEC(".maps");

int timer_result;

#if defined(__TARGET_ARCH_x86) && defined(__BPF_FEATURE_STACK_ARGUMENT)

const volatile bool has_stack_arg = true;

__noinline static long func_b(long a, long b, long c, long d,
			      long e, long f, long g, long h)
{
	return a + b + c + d + e + f + g + h;
}

__noinline static long func_a(long a, long b, long c, long d,
			      long e, long f, long g, long h)
{
	return func_b(a + 1, b + 1, c + 1, d + 1,
		      e + 1, f + 1, g + 1, h + 1);
}

SEC("tc")
int test(void)
{
	return func_a(a, b, c, d, e, f, g, i);
}

__noinline static int static_func_many_args(int a, int b, int c, int d,
					    int e, int f, int g, int h)
{
	return a + b + c + d + e + f + g + h;
}

__noinline int global_calls_many_args(int a, int b, int c)
{
	return static_func_many_args(a, b, c, 4, 5, 6, 7, 8);
}

SEC("tc")
int test_global_many_args(void)
{
	return global_calls_many_args(1, 2, 3);
}

static int timer_cb_many_args(void *map, int *key, struct bpf_timer *timer)
{
	timer_result = static_func_many_args(10, 20, 30, 40, 50, 60, 70, 80);
	return 0;
}

SEC("tc")
int test_async_cb_many_args(void)
{
	struct timer_elem *elem;
	int key = 0;

	elem = bpf_map_lookup_elem(&timer_map, &key);
	if (!elem)
		return -1;

	bpf_timer_init(&elem->timer, &timer_map, CLOCK_MONOTONIC);
	bpf_timer_set_callback(&elem->timer, timer_cb_many_args);
	bpf_timer_start(&elem->timer, 1, 0);
	return 0;
}

#else

const volatile bool has_stack_arg = false;

SEC("tc")
int test(void)
{
	return 0;
}

SEC("tc")
int test_global_many_args(void)
{
	return 0;
}

SEC("tc")
int test_async_cb_many_args(void)
{
	return 0;
}

#endif

char _license[] SEC("license") = "GPL";
