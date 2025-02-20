// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

void *bpf_cast_to_kern_ctx(void *) __ksym;
struct sk_buff *bpf_skb_acquire(struct sk_buff *skb) __ksym;
void bpf_skb_release(struct sk_buff *skb) __ksym;

struct skb_map_val {
	struct sk_buff __kptr * skb;
};

static __u32 get_idx;
static __u32 store_idx;

#define MAX_ENTRIES 100

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct skb_map_val);
	__uint(max_entries, MAX_ENTRIES);
} skb_map SEC(".maps");

static __always_inline __u32 idx_bump(__u32 idx)
{
	return idx >= MAX_ENTRIES ? 0 : idx + 1;
}

SEC("tc") int tc_skb_map_store(struct __sk_buff *ctx)
{
	struct sk_buff *skbk = bpf_cast_to_kern_ctx(ctx);
	struct skb_map_val *map_entry, tmp_entry;
	struct sk_buff *tmp;

	tmp_entry.skb = NULL;
	bpf_map_update_elem(&skb_map, &store_idx, &tmp_entry, BPF_ANY);
	map_entry = bpf_map_lookup_elem(&skb_map, &store_idx);
	if (!map_entry)
		return -1;

	skbk = bpf_skb_acquire(skbk);
	if (!skbk)
		return -2;

	tmp = bpf_kptr_xchg(&map_entry->skb, skbk);
	if (tmp)
		bpf_skb_release(tmp);

	store_idx = idx_bump(store_idx);

	return 0;
}

SEC("tc") int tc_skb_map_get(struct __sk_buff *ctx)
{
	struct sk_buff *stored_skb = NULL;
	struct skb_map_val *map_entry;
	struct sk_buff *tmp = NULL;

	(void)ctx;

	map_entry = bpf_map_lookup_elem(&skb_map, &get_idx);
	if (!map_entry)
		return -1;

	stored_skb = bpf_kptr_xchg(&map_entry->skb, tmp);
	if (!stored_skb)
		return -2;

	bpf_skb_release(stored_skb);
	get_idx = idx_bump(get_idx);

	return 0;
}

char _license[] SEC("license") = "GPL";
