// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_PIFO_GENERIC);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 10);
	__uint(map_extra, 1024); /* range */
} pifo_map SEC(".maps");

const volatile int num_entries = 10;
volatile int interval = 10;
volatile int start = 0;

SEC("xdp")
int pifo_dequeue(struct xdp_md *xdp)
{
	__u32 val, exp;
	int i, ret;

	for (i = 0; i < num_entries; i++) {
		exp = start + i * interval;
		ret = bpf_map_pop_elem(&pifo_map, &val);
		if (ret)
			return ret;
		if (val != exp)
			return 1;
	}

	return 0;
}

SEC("xdp")
int pifo_enqueue(struct xdp_md *xdp)
{
	__u64 flags;
	__u32 val;
	int i, ret;

	for (i = num_entries - 1; i >= 0; i--) {
		val = start + i * interval;
		flags = val;
		ret = bpf_map_push_elem(&pifo_map, &val, flags);
		if (ret)
			return ret;
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
