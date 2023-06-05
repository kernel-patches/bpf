// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */

#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <vmlinux.h>

#include "bpf_misc.h"

struct inner_map {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
} inner_map1 SEC(".maps"),
  inner_map2 SEC(".maps");

struct outer_hash {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, 2);
	__type(key, int);
	__array(values, struct inner_map);
} outer_hash SEC(".maps") = {
	.values = {
		[0] = &inner_map2,
		[1] = &inner_map1,
	},
};

SEC("tp_btf/task_newtask")
__failure
__msg("R2 type=scalar expected=func")
int BPF_PROG(test_iter_hash_of_maps_null_cb, struct task_struct *task, u64 clone_flags)
{
	/* Can't iterate over a NULL callback. */
	bpf_for_each_map_elem(&outer_hash, NULL, NULL, 0);
	return 0;
}
