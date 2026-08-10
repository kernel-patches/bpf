// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <linux/bpf.h>
#include <time.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

struct elem {
	struct bpf_timer t;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct elem);
} timer_map SEC(".maps");

__naked __noinline __used
static unsigned __int128 timer_cb_ret_pair(void *map, int *key, struct bpf_timer *timer)
{
	asm volatile (
		"r0 = 0;"
		"r2 = 0;"
		"exit;"
		::: __clobber_all
	);
}

SEC("fentry/bpf_fentry_test1")
__failure __msg("callback function with >8-byte return value is not supported")
__btf_func_path("btf__timer_ret_pair_fail.bpf.o")
long BPF_PROG2(test_bad_ret_pair, int, a)
{
	int key = 0;
	struct bpf_timer *timer;

	timer = bpf_map_lookup_elem(&timer_map, &key);
	if (timer) {
		bpf_timer_init(timer, &timer_map, CLOCK_BOOTTIME);
		bpf_timer_set_callback(timer, timer_cb_ret_pair);
	}

	return 0;
}
