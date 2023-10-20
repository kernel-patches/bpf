// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2023. Huawei Technologies Co., Ltd */
#include <linux/bpf.h>
#include <time.h>
#include <bpf/bpf_helpers.h>

#include "bpf_misc.h"

struct inner_value {
	struct bpf_timer timer;
};

struct inner_map_type {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct inner_value);
	__uint(max_entries, 1);
} inner_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, 1);
	__array(values, struct inner_map_type);
} outer_map SEC(".maps") = {
	.values = {
		[0] = &inner_map,
	},
};

char _license[] SEC("license") = "GPL";

int tgid = 0, cnt = 0;

SEC("kprobe/" SYS_PREFIX "sys_getpgid")
int do_timer_init(void *ctx)
{
	struct inner_map_type *map;
	struct inner_value *value;
	int zero = 0;

	if ((bpf_get_current_pid_tgid() >> 32) != tgid)
		return 0;

	map = bpf_map_lookup_elem(&outer_map, &zero);
	if (!map)
		return 0;
	value = bpf_map_lookup_elem(map, &zero);
	if (!value)
		return 0;
	bpf_timer_init(&value->timer, map, CLOCK_MONOTONIC);
	cnt++;

	return 0;
}
