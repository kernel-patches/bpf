#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define	IFNAMSIZ 16

int ifindex, ingress_ifindex;
char name[IFNAMSIZ];
unsigned int inum;
int meta_len, frag0_len;

extern void *bpf_get_kern_btf_id(void *, __u32) __ksym;

SEC("?xdp")
int md_xdp(struct xdp_md *ctx)
{
	struct xdp_buff *kctx = bpf_get_kern_btf_id(ctx, 0);
	struct net_device *dev;

	dev = kctx->rxq->dev;
	ifindex = dev->ifindex;
	inum = dev->nd_net.net->ns.inum;
	__builtin_memcpy(name, dev->name, IFNAMSIZ);
	ingress_ifindex = ctx->ingress_ifindex;
	return XDP_PASS;
}

SEC("?tc")
int md_skb(struct __sk_buff *skb)
{
	struct sk_buff *kskb = bpf_get_kern_btf_id(skb, 0);
	struct skb_shared_info *shared_info;

	/* Simulate the following kernel macro:
	 *   #define skb_shinfo(SKB) ((struct skb_shared_info *)(skb_end_pointer(SKB)))
	 */
	shared_info = bpf_get_kern_btf_id(kskb->head + kskb->end,
		bpf_core_type_id_kernel(struct skb_shared_info));
	meta_len = shared_info->meta_len;
	frag0_len = shared_info->frag_list->len;
	return 0;
}

char _license[] SEC("license") = "GPL";
