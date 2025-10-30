// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct lru_map {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, u64);
} lru_map SEC(".maps");

struct map_list {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__array(values, struct lru_map);
} map_list SEC(".maps") = {
	.values = { [0] = &lru_map },
};

const volatile int map_index;

static __always_inline void do_update_delete(void *map)
{
	u64 ts = bpf_ktime_get_ns();
	u32 key = (u32)(ts >> 12);
	u64 val = ts;

	if ((ts & 1) == 0)
		bpf_map_update_elem(map, &key, &val, BPF_ANY);
	else
		bpf_map_delete_elem(map, &key);
}

SEC("perf_event")
int on_perf(struct bpf_perf_event_data *ctx)
{
	int key = map_index;
	void *target_map;

	target_map = bpf_map_lookup_elem(&map_list, &key);
	if (!target_map)
		return 0;

	for (int i = 0; i < 4; i++)
		do_update_delete(target_map);
	return 0;
}
