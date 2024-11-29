// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>

long change_tail_ret = 1;

static __always_inline struct iphdr *parse_ip_header(struct __sk_buff *skb, int *ip_proto)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct ethhdr *eth = data;
	struct iphdr *iph;

	/* Verify Ethernet header */
	if ((void *)(data + sizeof(*eth)) > data_end)
		return NULL;

	/* Skip Ethernet header to get to IP header */
	iph = (void *)(data + sizeof(struct ethhdr));

	/* Verify IP header */
	if ((void *)(data + sizeof(struct ethhdr) + sizeof(*iph)) > data_end)
		return NULL;

	/* Basic IP header validation */
	if (iph->version != 4)  /* Only support IPv4 */
		return NULL;

	if (iph->ihl < 5)  /* Minimum IP header length */
		return NULL;

	*ip_proto = iph->protocol;
	return iph;
}

static __always_inline struct tcphdr *parse_tcp_header(struct __sk_buff *skb, struct iphdr *iph)
{
	void *data_end = (void *)(long)skb->data_end;
	void *hdr = (void *)iph;
	struct tcphdr *tcp;

	/* Calculate TCP header position */
	tcp = hdr + (iph->ihl * 4);
	hdr = (void *)tcp;

	/* Verify TCP header bounds */
	if ((void *)(hdr + sizeof(*tcp)) > data_end)
		return NULL;

	/* Basic TCP validation */
	if (tcp->doff < 5) /* Minimum TCP header length */
		return NULL;

	/* Success */
	return tcp;
}

SEC("tc")
int change_tail(struct __sk_buff *skb)
{
	int len = skb->len;
	struct tcphdr *tcp;
	struct iphdr *iph;
	void *data_end;
	char *payload;
	int ip_proto;

	bpf_skb_pull_data(skb, len);

	data_end = (void *)(long)skb->data_end;
	iph = parse_ip_header(skb, &ip_proto);
	if (!iph)
		return TC_ACT_OK;

	if (ip_proto != IPPROTO_TCP) /* Only support TCP packets */
		return TC_ACT_OK;

	tcp = parse_tcp_header(skb, iph);
	if (!tcp)
		return TC_ACT_OK;

	payload = (char *)tcp + (tcp->doff * 4);
	if (payload + 1 > (char *)data_end)
		return TC_ACT_OK;

	if (payload[0] == 'T') {
		change_tail_ret = bpf_skb_change_tail(skb, len - 1, 0);
		/* Change it back to make TCP happy */
		if (change_tail_ret == 0)
			bpf_skb_change_tail(skb, len, 0);
		return TC_ACT_OK;
	} else if (payload[0] == 'G') {
		change_tail_ret = bpf_skb_change_tail(skb, len + 1, 0);
		/* Change it back to make TCP happy */
		if (change_tail_ret == 0)
			bpf_skb_change_tail(skb, len, 0);
		return TC_ACT_OK;
	} else if (payload[0] == 'E') {
		change_tail_ret = bpf_skb_change_tail(skb, 65535, 0); /* Should fail */
		return TC_ACT_OK;
	} else if (payload[0] == 'Z') {
		change_tail_ret = bpf_skb_change_tail(skb, 0, 0); /* Should fail */
		return TC_ACT_OK;
	}
	return TC_ACT_SHOT;
}

char _license[] SEC("license") = "GPL";
