// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8);
	__type(key, __u32);
	__type(value, __u64);
} lru_map SEC(".maps");

int hits;

SEC("perf_event")
int oncpu(void *ctx)
{
	__u32 key = bpf_get_prandom_u32();
	__u64 val = 1;

	bpf_map_update_elem(&lru_map, &key, &val, BPF_ANY);
	__sync_fetch_and_add(&hits, 1);
	return 0;
}

char _license[] SEC("license") = "GPL";
