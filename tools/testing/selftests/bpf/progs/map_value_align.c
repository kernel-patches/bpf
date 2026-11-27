// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct lpm_key {
	__u32 prefixlen;
	__u32 data;
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 1);
	__type(key, struct lpm_key);
	__type(value, __u64);
} lpm SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} hash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct bpf_devmap_val);
} devmap SEC(".maps");

/* Addresses of the map values, checked by user space */
__u64 lpm_addr, hash_addr, devmap_addr;

SEC("xdp")
int lookup(struct xdp_md *ctx)
{
	struct lpm_key lkey = { .prefixlen = 32 };
	__u32 key = 0;

	lpm_addr = (unsigned long)bpf_map_lookup_elem(&lpm, &lkey);
	hash_addr = (unsigned long)bpf_map_lookup_elem(&hash, &key);
	devmap_addr = (unsigned long)bpf_map_lookup_elem(&devmap, &key);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
