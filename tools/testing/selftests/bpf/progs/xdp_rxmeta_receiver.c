// SPDX-License-Identifier: GPL-2.0
#define BPF_NO_KFUNC_PROTOTYPES
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

extern int bpf_xdp_metadata_rx_hash(const struct xdp_md *ctx, __u32 *hash,
				    enum xdp_rss_hash_type *rss_type) __ksym;
extern int bpf_xdp_metadata_rx_timestamp(const struct xdp_md *ctx,
					 __u64 *timestamp) __ksym;

#define RX_TIMESTAMP	0x12345678
#define RX_HASH		0x1234

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} stats SEC(".maps");

SEC("xdp")
int xdp_rxmeta_receiver(struct xdp_md *ctx)
{
	enum xdp_rss_hash_type rss_type;
	__u64 timestamp;
	__u32 hash;

	if (!bpf_xdp_metadata_rx_hash(ctx, &hash, &rss_type) &&
	    !bpf_xdp_metadata_rx_timestamp(ctx, &timestamp)) {
		if (hash == RX_HASH && rss_type == XDP_RSS_L4_TCP &&
		    timestamp == RX_TIMESTAMP) {
			__u32 *val, key = 0;

			val = bpf_map_lookup_elem(&stats, &key);
			if (val)
				 __sync_add_and_fetch(val, 1);
		}
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
