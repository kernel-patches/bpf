// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_CPUMAP);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct bpf_cpumap_val));
	__uint(max_entries, 1);
} cpu_map SEC(".maps");

SEC("xdp/cpumap")
int xdp_drop_prog(struct xdp_md *ctx)
{
	return XDP_DROP;
}

SEC("xdp")
int xdp_cpumap_prog(struct xdp_md *ctx)
{
	return bpf_redirect_map(&cpu_map, 0, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
