#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "bpf_kfuncs.h"

#define META_OFFSET (sizeof(struct ethhdr) + sizeof(struct iphdr))
#define META_SIZE 32

#define NF_DROP 0
#define NF_ACCEPT 1

#define ctx_ptr(ctx, mem) (void *)(unsigned long)ctx->mem

struct bpf_nf_ctx {
	struct sk_buff *skb;
} __attribute__((preserve_access_index));

/* Demonstrates how metadata can be passed from an XDP program to a TC program
 * using bpf_xdp_adjust_meta.
 * For the sake of testing the metadata support in drivers, the XDP program uses
 * a fixed-size payload after the Ethernet header as metadata. The TC program
 * copies the metadata it receives into a map so it can be checked from
 * userspace.
 */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__uint(value_size, META_SIZE);
} test_result SEC(".maps");

__u32 prog_run_cnt = 0;

static __always_inline int run_ok(int retval)
{
	__sync_fetch_and_add(&prog_run_cnt, 1);
	return retval;
}

SEC("tc")
int ing_cls(struct __sk_buff *ctx)
{
	__u8 *data, *data_meta;
	__u32 key = 0;

	data_meta = ctx_ptr(ctx, data_meta);
	data      = ctx_ptr(ctx, data);

	if (data_meta + META_SIZE > data)
		return TC_ACT_SHOT;

	bpf_map_update_elem(&test_result, &key, data_meta, BPF_ANY);

	return run_ok(TC_ACT_SHOT);
}

/* Read from metadata using bpf_dynptr_read helper */
SEC("tc")
int ing_cls_dynptr_read(struct __sk_buff *ctx)
{
	struct bpf_dynptr meta;
	const __u32 zero = 0;
	__u8 *dst;

	dst = bpf_map_lookup_elem(&test_result, &zero);
	if (!dst)
		return TC_ACT_SHOT;

	bpf_dynptr_from_skb_meta(ctx, 0, &meta);
	bpf_dynptr_read(dst, META_SIZE, &meta, 0, 0);

	return run_ok(TC_ACT_SHOT);
}

/* Check that we can't get a dynptr slice to skb metadata yet */
SEC("netfilter")
int ing_nf(struct bpf_nf_ctx *ctx)
{
	struct __sk_buff *skb = (struct __sk_buff *)ctx->skb;
	struct bpf_dynptr meta;

	bpf_dynptr_from_skb_meta(skb, 0, &meta);
	if (bpf_dynptr_size(&meta) != 0)
		return NF_DROP;

	return run_ok(NF_ACCEPT);
}

/* Write to metadata using bpf_dynptr_write helper */
SEC("tc")
int ing_cls_dynptr_write(struct __sk_buff *ctx)
{
	struct bpf_dynptr data, meta;
	__u8 *src;

	bpf_dynptr_from_skb(ctx, 0, &data);
	src = bpf_dynptr_slice(&data, META_OFFSET, NULL, META_SIZE);
	if (!src)
		return TC_ACT_SHOT;

	bpf_dynptr_from_skb_meta(ctx, 0, &meta);
	bpf_dynptr_write(&meta, 0, src, META_SIZE, 0);

	return run_ok(TC_ACT_UNSPEC); /* pass */
}

/* Read from metadata using read-only dynptr slice */
SEC("tc")
int ing_cls_dynptr_slice(struct __sk_buff *ctx)
{
	struct bpf_dynptr meta;
	const __u32 zero = 0;
	__u8 *dst, *src;

	dst = bpf_map_lookup_elem(&test_result, &zero);
	if (!dst)
		return TC_ACT_SHOT;

	bpf_dynptr_from_skb_meta(ctx, 0, &meta);
	src = bpf_dynptr_slice(&meta, 0, NULL, META_SIZE);
	if (!src)
		return TC_ACT_SHOT;

	__builtin_memcpy(dst, src, META_SIZE);

	return run_ok(TC_ACT_SHOT);
}

/* Write to metadata using writeable dynptr slice */
SEC("tc")
int ing_cls_dynptr_slice_rdwr(struct __sk_buff *ctx)
{
	struct bpf_dynptr data, meta;
	__u8 *src, *dst;

	bpf_dynptr_from_skb(ctx, 0, &data);
	src = bpf_dynptr_slice(&data, META_OFFSET, NULL, META_SIZE);
	if (!src)
		return TC_ACT_SHOT;

	bpf_dynptr_from_skb_meta(ctx, 0, &meta);
	dst = bpf_dynptr_slice_rdwr(&meta, 0, NULL, META_SIZE);
	if (!dst)
		return TC_ACT_SHOT;

	__builtin_memcpy(dst, src, META_SIZE);

	return run_ok(TC_ACT_UNSPEC); /* pass */
}

/*
 * Read skb metadata in chunks from various offsets in different ways.
 */
SEC("tc")
int ing_cls_dynptr_offset_rd(struct __sk_buff *ctx)
{
	struct bpf_dynptr meta;
	const __u32 chunk_len = META_SIZE / 4;
	const __u32 zero = 0;
	__u8 *dst, *src;

	dst = bpf_map_lookup_elem(&test_result, &zero);
	if (!dst)
		return TC_ACT_SHOT;

	/* 1. Regular read */
	bpf_dynptr_from_skb_meta(ctx, 0, &meta);
	bpf_dynptr_read(dst, chunk_len, &meta, 0, 0);
	dst += chunk_len;

	/* 2. Read from an offset-adjusted dynptr */
	bpf_dynptr_adjust(&meta, chunk_len, bpf_dynptr_size(&meta));
	bpf_dynptr_read(dst, chunk_len, &meta, 0, 0);
	dst += chunk_len;

	/* 3. Read at an offset */
	bpf_dynptr_read(dst, chunk_len, &meta, chunk_len, 0);
	dst += chunk_len;

	/* 4. Read from a slice starting at an offset */
	src = bpf_dynptr_slice(&meta, 2 * chunk_len, NULL, chunk_len);
	if (!src)
		return TC_ACT_SHOT;
	__builtin_memcpy(dst, src, chunk_len);

	return run_ok(TC_ACT_SHOT);
}

/* Write skb metadata in chunks at various offsets in different ways. */
SEC("tc")
int ing_cls_dynptr_offset_wr(struct __sk_buff *ctx)
{
	const __u32 chunk_len = META_SIZE / 4;
	__u8 payload[META_SIZE];
	struct bpf_dynptr meta;
	__u8 *dst, *src;

	bpf_skb_load_bytes(ctx, META_OFFSET, payload, sizeof(payload));
	src = payload;

	/* 1. Regular write */
	bpf_dynptr_from_skb_meta(ctx, 0, &meta);
	bpf_dynptr_write(&meta, 0, src, chunk_len, 0);
	src += chunk_len;

	/* 2. Write to an offset-adjusted dynptr */
	bpf_dynptr_adjust(&meta, chunk_len, bpf_dynptr_size(&meta));
	bpf_dynptr_write(&meta, 0, src, chunk_len, 0);
	src += chunk_len;

	/* 3. Write at an offset */
	bpf_dynptr_write(&meta, chunk_len, src, chunk_len, 0);
	src += chunk_len;

	/* 4. Write to a slice starting at an offset */
	dst = bpf_dynptr_slice_rdwr(&meta, 2 * chunk_len, NULL, chunk_len);
	if (!dst)
		return TC_ACT_SHOT;
	__builtin_memcpy(dst, src, chunk_len);

	return run_ok(TC_ACT_UNSPEC); /* pass */
}

/* Reserve and clear space for metadata but don't populate it */
SEC("xdp")
int ing_xdp_zalloc_meta(struct xdp_md *ctx)
{
	const void *data_end = ctx_ptr(ctx, data_end);
	const struct ethhdr *eth;
	const struct iphdr *iph;
	__u8 *meta;
	int ret;

	/* Expect Eth | IPv4 (proto=61) | ... */
	eth = ctx_ptr(ctx, data);
	if (eth + 1 > data_end || eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_DROP;
	iph = (void *)(eth + 1);
	if (iph + 1 > data_end || iph->protocol != 61)
		return XDP_DROP;

	ret = bpf_xdp_adjust_meta(ctx, -META_SIZE);
	if (ret < 0)
		return XDP_DROP;

	meta = ctx_ptr(ctx, data_meta);
	if (meta + META_SIZE > ctx_ptr(ctx, data))
		return XDP_DROP;

	__builtin_memset(meta, 0, META_SIZE);

	return run_ok(XDP_PASS);
}

SEC("xdp")
int ing_xdp(struct xdp_md *ctx)
{
	__u8 *data, *data_meta, *data_end, *payload;
	const struct ethhdr *eth;
	const struct iphdr *iph;
	int ret;

	ret = bpf_xdp_adjust_meta(ctx, -META_SIZE);
	if (ret < 0)
		return XDP_DROP;

	data_meta = ctx_ptr(ctx, data_meta);
	data_end  = ctx_ptr(ctx, data_end);
	data      = ctx_ptr(ctx, data);

	/* Expect Eth | IPv4 (proto=61) | meta blob */
	eth = (void *)data;
	if (eth + 1 > data_end || eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_DROP;
	iph = (void *)(eth + 1);
	if (iph + 1 > data_end || iph->protocol != 61)
		return XDP_DROP;
	payload = (void *)(iph + 1);
	if (payload + META_SIZE > data_end || data_meta + META_SIZE > data)
		return XDP_DROP;

	__builtin_memcpy(data_meta, payload, META_SIZE);
	return run_ok(XDP_PASS);
}

char _license[] SEC("license") = "GPL";
