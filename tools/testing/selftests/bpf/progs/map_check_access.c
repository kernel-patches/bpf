// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2021. Huawei Technologies Co., Ltd
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 */

#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* From include/linux/mm.h. */
#define FMODE_WRITE	0x2

const char bpf_metadata_test_var[] SEC(".rodata") = "test_var";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} data_input SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} data_input_w SEC(".maps");

char _license[] SEC("license") = "GPL";

SEC("lsm/bpf_map")
int BPF_PROG(check_access, struct bpf_map *map, fmode_t fmode)
{
	if (map != (struct bpf_map *)&data_input)
		return 0;

	if (fmode & FMODE_WRITE)
		return -EACCES;

	return 0;
}

SEC("struct_ops/test_1")
int BPF_PROG(test_1, struct bpf_dummy_ops_state *state)
{
	return 0;
}

SEC("struct_ops/test_2")
int BPF_PROG(test_2, struct bpf_dummy_ops_state *state, int a1,
	     unsigned short a2, char a3, unsigned long a4)
{
	return 0;
}

SEC(".struct_ops")
struct bpf_dummy_ops dummy_2 = {
	.test_1 = (void *)test_1,
	.test_2 = (void *)test_2,
};
