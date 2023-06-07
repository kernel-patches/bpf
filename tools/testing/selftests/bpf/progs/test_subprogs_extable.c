// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020 Facebook */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../bpf_testmod/bpf_testmod.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 8);
	__type(key, __u32);
	__type(value, __u64);
} test_array SEC(".maps");

static __u64 test_cb(struct bpf_map *map, __u32 *key, __u64 *val, void *data)
{
	return 1;
}

static __u64 test_cb2(struct bpf_map *map, __u32 *key, __u64 *val, void *data)
{
	return 1;
}

static __u64 test_cb3(struct bpf_map *map, __u32 *key, __u64 *val, void *data)
{
	return 1;
}

SEC("fexit/bpf_testmod_return_ptr")
int BPF_PROG(handle_fexit_ret_subprogs, int arg, struct file *ret)
{
	long buf = 0;

	bpf_probe_read_kernel(&buf, 8, ret);
	bpf_probe_read_kernel(&buf, 8, (char *)ret + 256);
	*(volatile long long *)ret;
	*(volatile int *)&ret->f_mode;
	bpf_for_each_map_elem(&test_array, test_cb, NULL, 0);
	return 0;
}

SEC("fexit/bpf_testmod_return_ptr")
int BPF_PROG(handle_fexit_ret_subprogs2, int arg, struct file *ret)
{
	long buf = 0;

	bpf_probe_read_kernel(&buf, 8, ret);
	bpf_probe_read_kernel(&buf, 8, (char *)ret + 256);
	*(volatile long long *)ret;
	*(volatile int *)&ret->f_mode;
	bpf_for_each_map_elem(&test_array, test_cb2, NULL, 0);
	return 0;
}

SEC("fexit/bpf_testmod_return_ptr")
int BPF_PROG(handle_fexit_ret_subprogs3, int arg, struct file *ret)
{
	long buf = 0;

	bpf_probe_read_kernel(&buf, 8, ret);
	bpf_probe_read_kernel(&buf, 8, (char *)ret + 256);
	*(volatile long long *)ret;
	*(volatile int *)&ret->f_mode;
	bpf_for_each_map_elem(&test_array, test_cb3, NULL, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
