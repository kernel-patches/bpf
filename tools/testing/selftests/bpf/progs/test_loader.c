// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u64);
} test_map SEC(".maps");

SEC("socket")
int probe(void *ctx)
{
	__u32 key = 0;
	__u64 *val = bpf_map_lookup_elem(&test_map, &key);

	return val ? (int)*val : 0;
}

char _license[] SEC("license") = "GPL";
