// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, unsigned long);
	__type(value, unsigned long);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} htab SEC(".maps");
