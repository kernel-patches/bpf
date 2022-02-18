// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define ETH_ALEN 6
const volatile int ifindex_out;
const volatile int ifindex_in;
const volatile __u8 expect_dst[ETH_ALEN];
volatile int pkts_seen_xdp = 0;
volatile int pkts_seen_tc = 0;
volatile int retcode = XDP_REDIRECT;

SEC("xdp")
int xdp_redirect(struct xdp_md *xdp)
{
	__u32 *metadata = (void *)(long)xdp->data_meta;
	void *data = (void *)(long)xdp->data;
	int ret = retcode;

	if (xdp->ingress_ifindex != ifindex_in)
		return XDP_ABORTED;

	if (metadata + 1 > data)
		return XDP_ABORTED;

	if (*metadata != 0x42)
		return XDP_ABORTED;

	if (bpf_xdp_adjust_meta(xdp, 4))
		return XDP_ABORTED;

	if (retcode > XDP_PASS)
		retcode--;

	if (ret == XDP_REDIRECT)
		return bpf_redirect(ifindex_out, 0);

	return ret;
}

static bool check_pkt(void *data, void *data_end)
{
	struct ethhdr *eth = data;
	struct ipv6hdr *iph = (void *)(eth + 1);
	struct udphdr *udp = (void *)(iph + 1);
	__u8 *payload = (void *)(udp + 1);

	if (payload + 1 > data_end)
		return false;

	if (iph->nexthdr != IPPROTO_UDP || *payload != 0x42)
		return false;

	/* reset the payload so the same packet doesn't get counted twice when
	 * it cycles back through the kernel path and out the dst veth
	 */
	*payload = 0;
	return true;
}

SEC("xdp")
int xdp_count_pkts(struct xdp_md *xdp)
{
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;

	if (check_pkt(data, data_end))
		pkts_seen_xdp++;

	return XDP_PASS;
}

SEC("tc")
int tc_count_pkts(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (check_pkt(data, data_end))
		pkts_seen_tc++;

	return 0;
}

char _license[] SEC("license") = "GPL";
