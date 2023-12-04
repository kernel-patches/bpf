// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_MMAPABLE);
	__type(key, uint32_t);
	__type(value, uintptr_t);
} ip SEC(".maps");

SEC("perf_event")
int handler(struct bpf_perf_event_data *data)
{
	const uint32_t index = 0;
	uintptr_t *v = bpf_map_lookup_elem(&ip, &index);

	return !(v && *v == PT_REGS_IP(&data->regs));
}

char _license[] SEC("license") = "GPL";
