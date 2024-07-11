// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct data_t {
        unsigned int d[12];
};

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10);
	__type(key, struct data_t);
	__type(value, struct data_t);
} htab SEC(".maps");

unsigned long hits = 0;

SEC("tp/syscalls/sys_enter_getpgid")
int stack0(void *ctx)
{
	struct data_t key = {}, value = {};
	struct data_t *pvalue;

	hits++;
	key.d[10] = 5;
	value.d[8] = 10;

	pvalue = bpf_map_lookup_elem(&htab, &key);
	if (!pvalue)
		bpf_map_update_elem(&htab, &key, &value, 0);
	bpf_map_delete_elem(&htab, &key);

	return 0;
}

