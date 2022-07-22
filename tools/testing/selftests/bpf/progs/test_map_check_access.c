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

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 1);
	__uint(map_flags, 0);
	__type(key, __u32);
	__type(value, __u32);
	__array(values, struct {
		__uint(type, BPF_MAP_TYPE_ARRAY);
		__uint(max_entries, 1);
		__type(key, int);
		__type(value, int);
	});
} data_input_mim SEC(".maps") = {
	.values = { (void *)&data_input },
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(key, int);
	__type(value, int);
} data_input_perf SEC(".maps");

char _license[] SEC("license") = "GPL";

SEC("iter/bpf_map_elem")
int dump_bpf_hash_map(struct bpf_iter__bpf_map_elem *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct bpf_map *map = ctx->map;
	u32 *key = ctx->key;
	u32 *val = ctx->value;

	if (key == (void *)0 || val == (void *)0)
		return 0;

	BPF_SEQ_PRINTF(seq, "%d: (%x) (%llx)\n", map->id, *key, *val);
	return 0;
}

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

SEC("tp/raw_syscalls/sys_enter")
int handle_sys_enter(void *ctx)
{
	int cpu = bpf_get_smp_processor_id();

	bpf_perf_event_output(ctx, &data_input_perf, BPF_F_CURRENT_CPU,
			      &cpu, sizeof(cpu));
	return 0;
}
