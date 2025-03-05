// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/const.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 3);
	__type(key, int);
	__type(value, int);
} size SEC(".maps");

SEC("xdp")
int _xdp_adjust_tail_grow(struct xdp_md *xdp)
{
	int data_len = bpf_xdp_get_buff_len(xdp);
	int offset = 0;
	int *page_size, *shinfo_size, *cache_linesize;
	int tailroom, key = 0;

	shinfo_size = bpf_map_lookup_elem(&size, &key);
	if (!shinfo_size)
		return XDP_ABORTED;
	key++;

	page_size = bpf_map_lookup_elem(&size, &key);
	if (!page_size)
		return XDP_ABORTED;
	key++;

	cache_linesize = bpf_map_lookup_elem(&size, &key);
	if (!cache_linesize)
		return XDP_ABORTED;

	/* SKB_DATA_ALIGN(sizeof(struct skb_shared_info)) */
	tailroom = __ALIGN_KERNEL(*shinfo_size, *cache_linesize);

	/* Data length determine test case */

	if (data_len == 54) { /* sizeof(pkt_v4) */
		offset = *page_size; /* test too large offset */
	} else if (data_len == 74) { /* sizeof(pkt_v6) */
		offset = 40;
	} else if (data_len == 64) {
		offset = 128;
	} else if (data_len == 128) {
		/* Max tail grow 3520 */
		offset = *page_size - 256 - tailroom - data_len;
	} else if (data_len == 9000) {
		offset = 10;
	} else if (data_len == 2 * (*page_size) + 1) {
		offset = *page_size;
	} else {
		return XDP_ABORTED; /* No matching test */
	}

	if (bpf_xdp_adjust_tail(xdp, offset))
		return XDP_DROP;
	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
