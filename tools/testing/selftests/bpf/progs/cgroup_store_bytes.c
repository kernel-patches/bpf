// SPDX-License-Identifier: GPL-2.0-only

#include <errno.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <bpf/bpf_helpers.h>

#define IP_SRC_OFF offsetof(struct iphdr, saddr)
#define UDP_SPORT_OFF (sizeof(struct iphdr) + offsetof(struct udphdr, source))

#define IS_PSEUDO 0x10

#define UDP_CSUM_OFF (sizeof(struct iphdr) + offsetof(struct udphdr, check))
#define IP_CSUM_OFF offsetof(struct iphdr, check)

int test_result = 0;

SEC("cgroup_skb/egress")
int cgroup_store_bytes(struct __sk_buff *skb)
{
	struct ethhdr eth;
	struct iphdr iph;
	struct udphdr udph;

	__u32 map_key = 0;
	__u16 new_port = 5555;
	__u16 old_port;
	__u32 old_ip;

	if (bpf_skb_load_bytes_relative(skb, 0, &iph, sizeof(iph), BPF_HDR_START_NET))
		goto fail;

	if (bpf_skb_load_bytes_relative(skb, sizeof(iph), &udph, sizeof(udph), BPF_HDR_START_NET))
		goto fail;

	old_port = udph.source;
	bpf_l4_csum_replace(skb, UDP_CSUM_OFF, old_port, new_port,
						IS_PSEUDO | sizeof(new_port));
	if (bpf_skb_store_bytes(skb, UDP_SPORT_OFF, &new_port, sizeof(new_port), 0) < 0)
		goto fail;

	test_result = 1;

fail:
	return 1;
}
