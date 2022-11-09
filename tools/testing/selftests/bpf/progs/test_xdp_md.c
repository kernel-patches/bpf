#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <string.h>

#define	IFNAMSIZ 16

int ifindex, ingress_ifindex;
char name[IFNAMSIZ];
unsigned int inum;

SEC("xdp")
int md_xdp(struct xdp_md *ctx)
{
	struct net_device *dev;

	dev = ctx->rx_dev;

	ifindex = dev->ifindex;
	inum = dev->nd_net.net->ns.inum;
	memcpy(name, dev->name, IFNAMSIZ);
	ingress_ifindex = ctx->ingress_ifindex;
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
