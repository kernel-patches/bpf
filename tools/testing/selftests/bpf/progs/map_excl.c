// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2023. Huawei Technologies Co., Ltd */
#include <linux/bpf.h>
#include <time.h>
#include <bpf/bpf_helpers.h>

#include "bpf_misc.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} excl_map SEC(".maps");

struct inner_map_type {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, 4);
	__uint(value_size, 4);
	__uint(max_entries, 1);
} inner_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, 1);
	__array(values, struct inner_map_type);
} outer_array_map SEC(".maps") = {
	.values = {
		[0] = &inner_map,
	},
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, 1);
	__array(values, struct inner_map_type);
} outer_htab_map SEC(".maps") = {
	.values = {
		[0] = &inner_map,
	},
};

char _license[] SEC("license") = "GPL";

SEC("?fentry.s/" SYS_PREFIX "sys_getpgid")
int should_have_access(void *ctx)
{
	int key = 0, value = 0xdeadbeef;

	bpf_map_update_elem(&excl_map, &key, &value, 0);
	return 0;
}

SEC("?fentry.s/" SYS_PREFIX "sys_getpgid")
int should_not_have_access(void *ctx)
{
	int key = 0, value = 0xdeadbeef;

	bpf_map_update_elem(&excl_map, &key, &value, 0);
	return 0;
}
