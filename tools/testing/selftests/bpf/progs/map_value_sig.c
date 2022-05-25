// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 */

#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_DATA_SIZE 1024
#define ARRAY_ELEMS 5

u32 verified_data_size;

struct data {
	u8 payload[MAX_DATA_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(map_flags, BPF_F_VERIFY_ELEM);
	__uint(max_entries, ARRAY_ELEMS);
	__type(key, __u32);
	__type(value, struct data);
} data_input SEC(".maps");

char _license[] SEC("license") = "GPL";

SEC("fexit/array_map_update_elem")
int BPF_PROG(array_map_update_elem, struct bpf_map *map, void *key, void *value,
	     u64 map_flags)
{
	struct data *data_ptr;
	int zero = 0;

	if (map != (struct bpf_map *)&data_input)
		return 0;

	data_ptr = bpf_map_lookup_elem(&data_input, &zero);
	if (!data_ptr)
		return 0;

	verified_data_size = bpf_map_verified_data_size((void *)data_ptr,
							sizeof(struct data));
	return 0;
}
