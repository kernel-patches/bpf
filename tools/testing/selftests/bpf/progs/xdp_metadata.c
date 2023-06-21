// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include "xdp_metadata.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u32);
} xsk SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} prog_arr SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 10);
} tx_compl_buf SEC(".maps");

__u64 pkts_fail_tx = 0;

int ifindex = -1;
__u64 net_cookie = -1;

extern int bpf_xdp_metadata_rx_timestamp(const struct xdp_md *ctx,
					 __u64 *timestamp) __ksym;
extern int bpf_xdp_metadata_rx_hash(const struct xdp_md *ctx, __u32 *hash,
				    enum xdp_rss_hash_type *rss_type) __ksym;
extern int bpf_devtx_sb_request_timestamp(const struct devtx_frame *ctx) __ksym;
extern int bpf_devtx_cp_timestamp(const struct devtx_frame *ctx, __u64 *timestamp) __ksym;

extern int bpf_devtx_sb_attach(int ifindex, int prog_fd) __ksym;
extern int bpf_devtx_cp_attach(int ifindex, int prog_fd) __ksym;

SEC("xdp")
int rx(struct xdp_md *ctx)
{
	void *data, *data_meta;
	struct xdp_meta *meta;
	u64 timestamp = -1;
	int ret;

	/* Reserve enough for all custom metadata. */

	ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct xdp_meta));
	if (ret != 0)
		return XDP_DROP;

	data = (void *)(long)ctx->data;
	data_meta = (void *)(long)ctx->data_meta;

	if (data_meta + sizeof(struct xdp_meta) > data)
		return XDP_DROP;

	meta = data_meta;

	/* Export metadata. */

	/* We expect veth bpf_xdp_metadata_rx_timestamp to return 0 HW
	 * timestamp, so put some non-zero value into AF_XDP frame for
	 * the userspace.
	 */
	bpf_xdp_metadata_rx_timestamp(ctx, &timestamp);
	if (timestamp == 0)
		meta->rx_timestamp = 1;

	bpf_xdp_metadata_rx_hash(ctx, &meta->rx_hash, &meta->rx_hash_type);

	return bpf_redirect_map(&xsk, ctx->rx_queue_index, XDP_PASS);
}

static inline int verify_frame(const struct devtx_frame *frame)
{
	struct ethhdr eth = {};

	/* all the pointers are set up correctly */
	if (!frame->data)
		return -1;
	if (!frame->sinfo)
		return -1;

	/* can get to the frags */
	if (frame->sinfo->nr_frags != 0)
		return -1;
	if (frame->sinfo->frags[0].bv_page != 0)
		return -1;
	if (frame->sinfo->frags[0].bv_len != 0)
		return -1;
	if (frame->sinfo->frags[0].bv_offset != 0)
		return -1;

	/* the data has something that looks like ethernet */
	if (frame->len != 46)
		return -1;
	bpf_probe_read_kernel(&eth, sizeof(eth), frame->data);

	if (eth.h_proto != bpf_htons(ETH_P_IP))
		return -1;

	return 0;
}

SEC("fentry/veth_devtx_submit")
int BPF_PROG(tx_submit, const struct devtx_frame *frame)
{
	struct xdp_tx_meta meta = {};
	int ret;

	if (frame->netdev->ifindex != ifindex)
		return 0;
	if (frame->netdev->nd_net.net->net_cookie != net_cookie)
		return 0;
	if (frame->meta_len != TX_META_LEN)
		return 0;

	bpf_probe_read_kernel(&meta, sizeof(meta), frame->data - TX_META_LEN);
	if (!meta.request_timestamp)
		return 0;

	ret = verify_frame(frame);
	if (ret < 0) {
		__sync_add_and_fetch(&pkts_fail_tx, 1);
		return 0;
	}

	ret = bpf_devtx_sb_request_timestamp(frame);
	if (ret < 0) {
		__sync_add_and_fetch(&pkts_fail_tx, 1);
		return 0;
	}

	return 0;
}

SEC("fentry/veth_devtx_complete")
int BPF_PROG(tx_complete, const struct devtx_frame *frame)
{
	struct xdp_tx_meta meta = {};
	struct devtx_sample *sample;
	int ret;

	if (frame->netdev->ifindex != ifindex)
		return 0;
	if (frame->netdev->nd_net.net->net_cookie != net_cookie)
		return 0;
	if (frame->meta_len != TX_META_LEN)
		return 0;

	bpf_probe_read_kernel(&meta, sizeof(meta), frame->data - TX_META_LEN);
	if (!meta.request_timestamp)
		return 0;

	ret = verify_frame(frame);
	if (ret < 0) {
		__sync_add_and_fetch(&pkts_fail_tx, 1);
		return 0;
	}

	sample = bpf_ringbuf_reserve(&tx_compl_buf, sizeof(*sample), 0);
	if (!sample)
		return 0;

	sample->timestamp_retval = bpf_devtx_cp_timestamp(frame, &sample->timestamp);

	bpf_ringbuf_submit(sample, 0);

	return 0;
}

char _license[] SEC("license") = "GPL";
