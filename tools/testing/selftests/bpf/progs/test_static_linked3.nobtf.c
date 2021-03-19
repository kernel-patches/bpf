// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* global variables don't need BTF to be used, but are extremely unconvenient
 * to be consumed from user-space without BPF skeleton, that uses BTF
 */

static volatile int mul3 = 3;
static volatile int add3 = 3;

/* same "subprog" name in all files */
static __noinline int subprog(int x)
{
	/* but different formula */
	return x * mul3 + add3;
}

struct bpf_map_def SEC("maps") legacy_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 1,
};

SEC("raw_tp/sys_enter")
int handler3(const void *ctx)
{
	int key = 0, value = subprog(1);

	bpf_map_update_elem(&legacy_map, &key, &value, BPF_ANY);

	return 0;
}
