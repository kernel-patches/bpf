// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */
#include "bpf_iter.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 3);
	__type(key, __u32);
	__type(value, __u64);
} hashmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} percpu_map SEC(".maps");

struct callback_ctx {
	struct bpf_iter__task *ctx;
	int input;
	int output;
};

static __u64
check_hash_elem(struct bpf_map *map, __u32 *key, __u64 *val,
		struct callback_ctx *data)
{
	struct bpf_iter__task *ctx = data->ctx;
	__u32 k;
	__u64 v;

	if (ctx) {
		k = *key;
		v = *val;
		if (ctx->meta->seq_num == 10 && k == 10 && v == 10)
			data->output = 3; /* impossible path */
		else
			data->output = 4;
	} else {
		data->output = data->input;
		bpf_map_delete_elem(map, key);
	}

	return 0;
}

__u32 cpu = 0;
__u32 percpu_called = 0;
__u32 percpu_key = 0;
__u64 percpu_val = 0;

static __u64
check_percpu_elem(struct bpf_map *map, __u32 *key, __u64 *val,
		  struct callback_ctx *data)
{
	percpu_called++;
	cpu = bpf_get_smp_processor_id();
	percpu_key = *key;
	percpu_val = *val;

	bpf_for_each_map_elem(&hashmap, check_hash_elem, data, 0);
	return 0;
}

int called = 0;
int hashmap_output = 0;
int percpu_output = 0;

SEC("iter/task")
int dump_task(struct bpf_iter__task *ctx)
{
	struct seq_file *seq =  ctx->meta->seq;
	struct task_struct *task = ctx->task;
	struct callback_ctx data;
	int ret;

	/* only call once since we will delete map elements */
	if (task == (void *)0 || called > 0)
		return 0;

	called++;

	data.ctx = ctx;
	data.input = task->tgid;
	data.output = 0;
	ret = bpf_for_each_map_elem(&hashmap, check_hash_elem, &data, 0);
	if (ret)
		return 0;

	hashmap_output = data.output;

	data.ctx = 0;
	data.input = 100;
	data.output = 0;
	bpf_for_each_map_elem(&percpu_map, check_percpu_elem, &data, 0);
	percpu_output = data.output;

	return 0;
}
