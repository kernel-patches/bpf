// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>

int lookup_status;
bool tcp_skc;

#define CUR_NS BPF_F_CURRENT_NETNS

SEC("tc")
int test_socket_lookup(struct __sk_buff *skb)
{
	struct bpf_sock_tuple *tp;
	void *data_end, *data;
	struct bpf_sock *sk;
	struct ethhdr *eth;
	struct iphdr *iph;
	int tplen;

	if (skb->protocol != bpf_htons(ETH_P_IP))
		return TC_ACT_UNSPEC;

	tplen = sizeof(tp->ipv4);

	if (bpf_skb_pull_data(skb, sizeof(*eth) + sizeof(*iph) + tplen))
		return TC_ACT_SHOT;

	data_end = (void *)(long)skb->data_end;
	data = (void *)(long)skb->data;

	eth = data;
	if (eth + 1 > data_end)
		return TC_ACT_SHOT;

	iph = (struct iphdr *)(eth + 1);
	if (iph + 1 > data_end)
		return TC_ACT_SHOT;

	tp = (struct bpf_sock_tuple *)&iph->saddr;
	if ((void *)tp + tplen > data_end)
		return TC_ACT_SHOT;

	switch (iph->protocol) {
	case IPPROTO_TCP:
		if (tcp_skc)
			sk = bpf_skc_lookup_tcp(skb, tp, tplen, CUR_NS, 0);
		else
			sk = bpf_sk_lookup_tcp(skb, tp, tplen, CUR_NS, 0);
		break;
	case IPPROTO_UDP:
		sk = bpf_sk_lookup_udp(skb, tp, tplen, CUR_NS, 0);
		break;
	default:
		return TC_ACT_SHOT;
	}

	lookup_status = 0;

	if (sk) {
		bpf_sk_release(sk);
		lookup_status = 1;
	}

	return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";
