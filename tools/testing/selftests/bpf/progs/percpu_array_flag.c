// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, int);
	__type(value, u64);
} percpu SEC(".maps");

SEC("fentry/bpf_fentry_test1")
int BPF_PROG(test_percpu_array, int x)
{
	u64 value = 0xDEADC0DE;
	int key = 0;

	bpf_map_update_elem(&percpu, &key, &value, BPF_ANY);
	return 0;
}

char _license[] SEC("license") = "GPL";

