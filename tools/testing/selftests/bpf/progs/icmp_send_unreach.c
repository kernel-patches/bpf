// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int unreach_code = 0;

#define SERVER_PORT 54321
#define SERVER_IP 0x7F000001

SEC("cgroup_skb/egress")
int egress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct iphdr *iph;
	struct tcphdr *tcph;

	iph = data;
	if ((void *)(iph + 1) > data_end || iph->version != 4 ||
	    iph->protocol != IPPROTO_TCP || iph->daddr != bpf_htonl(SERVER_IP))
		return SK_PASS;

	tcph = (void *)iph + iph->ihl * 4;
	if ((void *)(tcph + 1) > data_end ||
	    tcph->dest != bpf_htons(SERVER_PORT))
		return SK_PASS;

	bpf_icmp_send_unreach(skb, unreach_code);

	/* returns SK_PASS to execute the test case quicker */
	return SK_PASS;
}
