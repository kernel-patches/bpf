// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_hash(struct xdp_md *xdp)
{
	struct bpf_packet_hash_params hashp = {
		.hash = BPF_CRC32C,
		.initial = ~0,
		.offset = 0,
		.len = bpf_xdp_get_buff_len(xdp),
	};
	__u32 hash = 0;
	__u8 *data_end = (__u8 *)(void *)(long)xdp->data_end;
	__u8 *data = (__u8 *)(void *)(long)xdp->data;

	if (bpf_xdp_packet_hash(xdp, &hashp, &hash, sizeof(hash)) < 0)
		return XDP_DROP;
	data_end = (__u8 *)(void *)(long)xdp->data_end;
	data = (__u8 *)(void *)(long)xdp->data;
	if (data + sizeof(hash) > data_end)
		return XDP_DROP;
	*(__u32 *)data = hash ^ ~0;
	return XDP_PASS;
}

SEC("xdp")
int xdp_hash_oob(struct xdp_md *xdp)
{
	struct bpf_packet_hash_params hashp = {
		.hash = BPF_CRC32C,
		.initial = ~0,
		.offset = 0,
		.len = bpf_xdp_get_buff_len(xdp),
	};
	__u32 hash = 0;
	__u8 *data_end = (__u8 *)(void *)(long)xdp->data_end;
	__u8 *data = (__u8 *)(void *)(long)xdp->data;
	int *ret = NULL;

	if (data + (5 * sizeof(int)) >= data_end)
		return -1;
	ret = (int *)(void *)(long)xdp->data;
	/* Generate EINVAL for output not being 4 bytes for a crc32c checksum */
	*ret++ = bpf_xdp_packet_hash(xdp, &hashp, &hash, 1);

	/* Try an unsupported hash algo for ENOTSUPP */
	hashp.hash = BPF_HASH_UNSPEC;
	*ret++ = bpf_xdp_packet_hash(xdp, &hashp, &hash, sizeof(hash));

	/* Generate EFAULT for offset being over 0xffff */
	hashp.offset = ~0;
	*ret++ = bpf_xdp_packet_hash(xdp, &hashp, &hash, sizeof(hash));

	/* Generate ERANGE for being over buf length */
	hashp.offset = hashp.len + 1;
	*ret++ = bpf_xdp_packet_hash(xdp, &hashp, &hash, sizeof(hash));
	hashp.offset = 0;
	hashp.len += 1;
	*ret++ = bpf_xdp_packet_hash(xdp, &hashp, &hash, sizeof(hash));
	return 0;
}

SEC("tc")
int skb_hash(struct __sk_buff *skb)
{
	__u32 hash = 0;
	__u8 *data_end = (__u8 *)(void *)(long)skb->data_end;
	__u8 *data = (__u8 *)(void *)(long)skb->data;
	struct bpf_packet_hash_params hashp = {
		.hash = BPF_CRC32C,
		.initial = ~0,
		.offset = 0,
		.len = data_end - data,
	};

	if (bpf_skb_packet_hash(skb, &hashp, &hash, sizeof(hash)) < 0)
		return TC_ACT_SHOT;

	if (data + sizeof(hash) > data_end)
		return TC_ACT_SHOT;
	*(__u32 *)data = hash ^ ~0;
	return TC_ACT_OK;
}

SEC("tc")
int skb_hash_oob(struct __sk_buff *skb)
{
	__u32 hash = 0;
	__u8 *data_end = (__u8 *)(void *)(long)skb->data_end;
	__u8 *data = (__u8 *)(void *)(long)skb->data;
	struct bpf_packet_hash_params hashp = {
		.hash = BPF_CRC32C,
		.initial = ~0,
		.offset = 0,
		.len = data_end - data,
	};
	int *ret = NULL;

	if (data + (5 * sizeof(int)) >= data_end)
		return -1;
	ret = (int *)(void *)(long)skb->data;
	/* Generate EINVAL for output not being 4 bytes for a crc32c checksum */
	*ret++ = bpf_skb_packet_hash(skb, &hashp, &hash, 1);

	/* Try an unsupported hash algo for ENOTSUPP */
	hashp.hash = BPF_HASH_UNSPEC;
	*ret++ = bpf_skb_packet_hash(skb, &hashp, &hash, sizeof(hash));

	/* Generate EFAULT for offset being over 0xffff */
	hashp.offset = ~0;
	*ret++ = bpf_skb_packet_hash(skb, &hashp, &hash, sizeof(hash));

	/* Generate ERANGE for being over buf length */
	hashp.offset = hashp.len + 1;
	*ret++ = bpf_skb_packet_hash(skb, &hashp, &hash, sizeof(hash));
	hashp.offset = 0;
	hashp.len += 1;
	*ret++ = bpf_skb_packet_hash(skb, &hashp, &hash, sizeof(hash));
	return 0;
}

char _license[] SEC("license") = "GPL";
