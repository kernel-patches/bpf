// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include "xdp_skb_ext.h"
#include <errno.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

#define HDR_SZ 4
#define HASH_SZ 8
#define VLAN_SZ 4
#define CSUM_SZ 4
#define EXT_SZ (HDR_SZ + HASH_SZ + VLAN_SZ + CSUM_SZ)

static int store_hash(struct xdp_md *ctx)
{
	return bpf_xdp_skb_ext_store_rx_hash(ctx, 1, XDP_RSS_TYPE_L4_IPV4_TCP);
}

static int store_vlan(struct xdp_md *ctx)
{
	return bpf_xdp_skb_ext_store_rx_vlan(ctx, bpf_htons(ETH_P_8021Q), 1);
}

static int store_csum(struct xdp_md *ctx)
{
	return bpf_xdp_skb_ext_store_rx_csum(ctx, XDP_CHECKSUM_UNNECESSARY,
					     SKB_MAX_CSUM_LEVEL);
}

static int store_all(struct xdp_md *ctx)
{
	int ret;

	ret = store_hash(ctx);
	if (!ret)
		ret = store_vlan(ctx);
	if (!ret)
		ret = store_csum(ctx);
	return ret;
}

/* Leave @len bytes of headroom above data_meta */
static int leave_headroom(struct xdp_md *ctx, int len)
{
	return bpf_xdp_adjust_meta(ctx, -(MAX_META_LEN - len));
}

/*
 * The test run copies data_meta out, so give the room back. Not inlined:
 * clang would read ctx through a modified ctx pointer, which the verifier
 * rejects.
 */
static __noinline int restore_meta(struct xdp_md *ctx, int ret)
{
	bpf_xdp_adjust_meta(ctx, ctx->data - ctx->data_meta);
	return ret;
}

/* A second store of the same id takes the same place */
SEC("xdp")
__success __retval(0)
int store_same_id(struct xdp_md *ctx)
{
	int ret;

	ret = store_all(ctx);
	if (!ret)
		ret = store_hash(ctx);
	if (!ret)
		ret = leave_headroom(ctx, EXT_SZ);
	return restore_meta(ctx, ret);
}

SEC("xdp")
__success __retval(-EINVAL)
int adjust_meta_into_area(struct xdp_md *ctx)
{
	int ret;

	ret = store_all(ctx);
	if (!ret)
		ret = leave_headroom(ctx, EXT_SZ - CSUM_SZ);
	return restore_meta(ctx, ret);
}

SEC("xdp")
__success __retval(0)
int adjust_head_to_area(struct xdp_md *ctx)
{
	int ret;

	ret = store_all(ctx);
	if (!ret)
		ret = bpf_xdp_adjust_head(ctx, -(MAX_META_LEN - EXT_SZ));
	if (!ret)
		bpf_xdp_adjust_head(ctx, MAX_META_LEN - EXT_SZ);
	return ret;
}

SEC("xdp")
__success __retval(-EINVAL)
int adjust_head_into_area(struct xdp_md *ctx)
{
	int ret;

	ret = store_all(ctx);
	if (!ret)
		ret = bpf_xdp_adjust_head(ctx, -(MAX_META_LEN - EXT_SZ + 1));
	return ret;
}

SEC("xdp")
__success __retval(-EINVAL)
int csum_complete(struct xdp_md *ctx)
{
	return bpf_xdp_skb_ext_store_rx_csum(ctx, XDP_CHECKSUM_COMPLETE, 0);
}

SEC("xdp")
__success __retval(-EINVAL)
int csum_none_level1(struct xdp_md *ctx)
{
	return bpf_xdp_skb_ext_store_rx_csum(ctx, XDP_CHECKSUM_NONE, 1);
}

SEC("xdp")
__success __retval(-EINVAL)
int csum_level_too_big(struct xdp_md *ctx)
{
	return bpf_xdp_skb_ext_store_rx_csum(ctx, XDP_CHECKSUM_UNNECESSARY,
					     SKB_MAX_CSUM_LEVEL + 1);
}

SEC("xdp")
__success __retval(-EINVAL)
int vlan_bad_proto(struct xdp_md *ctx)
{
	return bpf_xdp_skb_ext_store_rx_vlan(ctx, bpf_htons(0x1234), 1);
}

SEC("xdp")
__success __retval(-EINVAL)
int del_bad_id(struct xdp_md *ctx)
{
	return bpf_xdp_skb_ext_del(ctx, XDP_SKB_EXT_NUM);
}

/* Failed calls do not create the area */
SEC("xdp")
__success __retval(0)
int einval_no_area(struct xdp_md *ctx)
{
	bpf_xdp_skb_ext_store_rx_csum(ctx, XDP_CHECKSUM_COMPLETE, 0);
	bpf_xdp_skb_ext_store_rx_vlan(ctx, bpf_htons(0x1234), 1);
	bpf_xdp_skb_ext_del(ctx, XDP_SKB_EXT_NUM);
	return restore_meta(ctx, leave_headroom(ctx, 0));
}

SEC("xdp")
__success __retval(0)
int enospc_smaller_fits(struct xdp_md *ctx)
{
	int ret;

	ret = leave_headroom(ctx, HDR_SZ + VLAN_SZ);
	if (!ret && store_hash(ctx) != -ENOSPC)
		ret = -1;
	if (!ret)
		ret = store_vlan(ctx);
	return restore_meta(ctx, ret);
}

SEC("xdp")
__success __retval(-ENOSPC)
int enospc_full(struct xdp_md *ctx)
{
	int ret;

	ret = leave_headroom(ctx, HDR_SZ + VLAN_SZ);
	if (!ret)
		ret = store_vlan(ctx);
	if (!ret)
		ret = store_csum(ctx);
	return restore_meta(ctx, ret);
}

/* Without the area, a delete must not write where the header would be */
SEC("xdp")
__success __retval(0)
int del_no_area(struct xdp_md *ctx)
{
	__u32 *meta;
	int ret;

	if (leave_headroom(ctx, 0))
		return -1;
	meta = (void *)(long)ctx->data_meta;
	if (meta + 1 > (__u32 *)(long)ctx->data)
		return restore_meta(ctx, -1);
	*meta = ~0U;
	ret = bpf_xdp_skb_ext_del(ctx, XDP_SKB_EXT_HASH);
	meta = (void *)(long)ctx->data_meta;
	if (meta + 1 > (__u32 *)(long)ctx->data)
		return restore_meta(ctx, -1);
	if (!ret && *meta != ~0U)
		ret = -1;
	return restore_meta(ctx, ret);
}

/* A delete does not shrink the area */
SEC("xdp")
__success __retval(-ENOSPC)
int del_keeps_area(struct xdp_md *ctx)
{
	int ret;

	ret = leave_headroom(ctx, HDR_SZ + HASH_SZ);
	if (!ret)
		ret = store_hash(ctx);
	if (!ret)
		ret = bpf_xdp_skb_ext_del(ctx, XDP_SKB_EXT_HASH);
	if (!ret)
		ret = store_vlan(ctx);
	return restore_meta(ctx, ret);
}

/* A deleted entry keeps its place */
SEC("xdp")
__success __retval(0)
int del_reuse(struct xdp_md *ctx)
{
	int ret;

	ret = leave_headroom(ctx, HDR_SZ + HASH_SZ);
	if (!ret)
		ret = store_hash(ctx);
	if (!ret)
		ret = bpf_xdp_skb_ext_del(ctx, XDP_SKB_EXT_HASH);
	if (!ret)
		ret = store_hash(ctx);
	return restore_meta(ctx, ret);
}

char _license[] SEC("license") = "GPL";
