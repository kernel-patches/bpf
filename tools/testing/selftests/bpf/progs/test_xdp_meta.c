#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define __round_mask(x, y) ((__typeof__(x))((y) - 1))
#define round_up(x, y) ((((x) - 1) | __round_mask(x, y)) + 1)
#define ctx_ptr(ctx, mem) (void *)(unsigned long)ctx->mem

SEC("tc")
int ing_cls(struct __sk_buff *ctx)
{
	__u8 *data, *data_meta, *data_end;
	__u32 diff = 0;

	data_meta = ctx_ptr(ctx, data_meta);
	data_end  = ctx_ptr(ctx, data_end);
	data      = ctx_ptr(ctx, data);

	if (data + ETH_ALEN > data_end ||
	    data_meta + round_up(ETH_ALEN, 4) > data)
		return TC_ACT_SHOT;

	diff |= ((__u32 *)data_meta)[0] ^ ((__u32 *)data)[0];
	diff |= ((__u16 *)data_meta)[2] ^ ((__u16 *)data)[2];

	return diff ? TC_ACT_SHOT : TC_ACT_OK;
}

SEC("xdp")
int ing_xdp(struct xdp_md *ctx)
{
	__u8 *data, *data_meta, *data_end;
	int ret;

	ret = bpf_xdp_adjust_meta(ctx, -round_up(ETH_ALEN, 4));
	if (ret < 0)
		return XDP_DROP;

	data_meta = ctx_ptr(ctx, data_meta);
	data_end  = ctx_ptr(ctx, data_end);
	data      = ctx_ptr(ctx, data);

	if (data + ETH_ALEN > data_end ||
	    data_meta + round_up(ETH_ALEN, 4) > data)
		return XDP_DROP;

	__builtin_memcpy(data_meta, data, ETH_ALEN);
	return XDP_PASS;
}

#define TEST_META_THRESH	128

SEC("xdp")
int ing_hints(struct xdp_md *ctx)
{
	const struct xdp_meta_generic *md;
	__le64 genid;

	md = bpf_access_mem_end(ctx->data_meta, ctx->data, sizeof(*md),
				sizeof(*md));

	/* Selftest enables metadata starting from 128 byte frame size, fail it
	 * if we receive a shorter frame with metadata
	 */
	if (ctx->data_end - ctx->data < TEST_META_THRESH)
		return md ? XDP_DROP : XDP_PASS;

	if (!md)
		return XDP_DROP;

	if (md->magic_id != bpf_cpu_to_le16(XDP_META_GENERIC_MAGIC))
		return XDP_DROP;

	genid = bpf_cpu_to_le64(bpf_core_type_id_kernel(typeof(*md)));
	if (md->full_id != genid)
		return XDP_DROP;

	/* Tx flags must be zeroed */
	if (md->tx_flags)
		return XDP_DROP;

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
