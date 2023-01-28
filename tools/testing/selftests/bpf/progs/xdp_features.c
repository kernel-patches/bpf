// SPDX-License-Identifier: GPL-2.0

#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/netdev.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/udp.h>
#include <asm-generic/errno-base.h>

#include "xdp_features.h"

#define ipv6_addr_equal(a, b)	((a).s6_addr32[0] == (b).s6_addr32[0] &&	\
				 (a).s6_addr32[1] == (b).s6_addr32[1] &&	\
				 (a).s6_addr32[2] == (b).s6_addr32[2] &&	\
				 (a).s6_addr32[3] == (b).s6_addr32[3])

struct net_device;
struct bpf_prog;

struct xdp_cpumap_stats {
	unsigned int redirect;
	unsigned int pass;
	unsigned int drop;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} dut_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_CPUMAP);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct bpf_cpumap_val));
	__uint(max_entries, 1);
} cpu_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct bpf_devmap_val));
	__uint(max_entries, 1);
} dev_map SEC(".maps");

const volatile __u32 expected_feature = XDP_FEATURE_PASS;
const volatile union {
	struct in_addr ip;
	struct in6_addr ip6;
} tester_addr;
const volatile union {
	struct in_addr ip;
	struct in6_addr ip6;
} dut_addr;

static __always_inline int xdp_process_echo_packet(struct xdp_md *xdp, bool dut)
{
	void *data_end = (void *)(long)xdp->data_end;
	void *data = (void *)(long)xdp->data;
	struct ethhdr *eh = data;
	struct tlv_hdr *tlv;
	struct udphdr *uh;
	__be16 port;
	__u8 *cmd;

	if (eh + 1 > (struct ethhdr *)data_end)
		return -EINVAL;

	if (eh->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ih = (struct iphdr *)(eh + 1);
		__be32 saddr = dut ? tester_addr.ip.s_addr : dut_addr.ip.s_addr;
		__be32 daddr = dut ? dut_addr.ip.s_addr : tester_addr.ip.s_addr;

		ih = (struct iphdr *)(eh + 1);
		if (ih + 1 > (struct iphdr *)data_end)
			return -EINVAL;

		if (saddr != ih->saddr)
			return -EINVAL;

		if (daddr != ih->daddr)
			return -EINVAL;

		if (ih->protocol != IPPROTO_UDP)
			return -EINVAL;

		uh = (struct udphdr *)(ih + 1);
	} else if (eh->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct in6_addr saddr = dut ? tester_addr.ip6 : dut_addr.ip6;
		struct in6_addr daddr = dut ? dut_addr.ip6 : tester_addr.ip6;
		struct ipv6hdr *ih6 = (struct ipv6hdr *)(eh + 1);

		if (ih6 + 1 > (struct ipv6hdr *)data_end)
			return -EINVAL;

		if (!ipv6_addr_equal(saddr, ih6->saddr))
			return -EINVAL;

		if (!ipv6_addr_equal(daddr, ih6->daddr))
			return -EINVAL;

		if (ih6->nexthdr != IPPROTO_UDP)
			return -EINVAL;

		uh = (struct udphdr *)(ih6 + 1);
	} else {
		return -EINVAL;
	}

	if (uh + 1 > (struct udphdr *)data_end)
		return -EINVAL;

	port = dut ? uh->dest : uh->source;
	if (port != bpf_htons(DUT_ECHO_PORT))
		return -EINVAL;

	tlv = (struct tlv_hdr *)(uh + 1);
	if (tlv + 1 > data_end)
		return -EINVAL;

	return bpf_htons(tlv->type) == CMD_ECHO ? 0 : -EINVAL;
}

SEC("xdp")
int xdp_tester(struct xdp_md *xdp)
{
	__u32 *val, key = 0;

	switch (expected_feature) {
	case XDP_FEATURE_NDO_XMIT:
	case XDP_FEATURE_TX:
		if (xdp_process_echo_packet(xdp, true))
			goto out;
		break;
	case XDP_FEATURE_DROP:
	case XDP_FEATURE_PASS:
	case XDP_FEATURE_REDIRECT:
		if (xdp_process_echo_packet(xdp, false))
			goto out;
		break;
	default:
		goto out;
	}

	val = bpf_map_lookup_elem(&stats, &key);
	if (val)
		__sync_add_and_fetch(val, 1);

out:
	return XDP_PASS;
}

SEC("xdp")
int xdp_do_pass(struct xdp_md *xdp)
{
	__u32 *val, key = 0;

	val = bpf_map_lookup_elem(&dut_stats, &key);
	if (val)
		__sync_add_and_fetch(val, 1);

	return XDP_PASS;
}

SEC("xdp")
int xdp_do_drop(struct xdp_md *xdp)
{
	__u32 *val, key = 0;

	if (xdp_process_echo_packet(xdp, true))
		return XDP_PASS;

	val = bpf_map_lookup_elem(&dut_stats, &key);
	if (val)
		__sync_add_and_fetch(val, 1);

	return XDP_DROP;
}

SEC("xdp")
int xdp_do_aborted(struct xdp_md *xdp)
{
	return xdp_process_echo_packet(xdp, true) ? XDP_PASS : XDP_ABORTED;
}

SEC("xdp")
int xdp_do_tx(struct xdp_md *xdp)
{
	void *data = (void *)(long)xdp->data;
	struct ethhdr *eh = data;
	__u8 tmp_mac[ETH_ALEN];
	__u32 *val, key = 0;

	if (xdp_process_echo_packet(xdp, true))
		return XDP_PASS;

	__builtin_memcpy(tmp_mac, eh->h_source, ETH_ALEN);
	__builtin_memcpy(eh->h_source, eh->h_dest, ETH_ALEN);
	__builtin_memcpy(eh->h_dest, tmp_mac, ETH_ALEN);

	val = bpf_map_lookup_elem(&dut_stats, &key);
	if (val)
		__sync_add_and_fetch(val, 1);

	return XDP_TX;
}

SEC("xdp")
int xdp_do_redirect(struct xdp_md *xdp)
{
	if (xdp_process_echo_packet(xdp, true))
		return XDP_PASS;

	return bpf_redirect_map(&cpu_map, 0, 0);
}

SEC("tp_btf/xdp_exception")
int BPF_PROG(xdp_exception, const struct net_device *dev,
	     const struct bpf_prog *xdp, __u32 act)
{
	__u32 *val, key = 0;

	val = bpf_map_lookup_elem(&dut_stats, &key);
	if (val)
		__sync_add_and_fetch(val, 1);

	return 0;
}

SEC("tp_btf/xdp_cpumap_kthread")
int BPF_PROG(tp_xdp_cpumap_kthread, int map_id, unsigned int processed,
	     unsigned int drops, int sched, struct xdp_cpumap_stats *xdp_stats)
{
	__u32 *val, key = 0;

	val = bpf_map_lookup_elem(&dut_stats, &key);
	if (val)
		__sync_add_and_fetch(val, 1);

	return 0;
}

SEC("xdp/cpumap")
int xdp_do_redirect_cpumap(struct xdp_md *xdp)
{
	void *data = (void *)(long)xdp->data;
	struct ethhdr *eh = data;
	__u8 tmp_mac[ETH_ALEN];

	if (xdp_process_echo_packet(xdp, true))
		return XDP_PASS;

	__builtin_memcpy(tmp_mac, eh->h_source, ETH_ALEN);
	__builtin_memcpy(eh->h_source, eh->h_dest, ETH_ALEN);
	__builtin_memcpy(eh->h_dest, tmp_mac, ETH_ALEN);

	return bpf_redirect_map(&dev_map, 0, 0);
}

char _license[] SEC("license") = "GPL";
