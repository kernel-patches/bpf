// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u64);
} sock_ops_map SEC(".maps");

SEC("sockops")
int bpf_sockmap(struct bpf_sock_ops *skops)
{
	return 0;
}

char _license[] SEC("license") = "GPL";
