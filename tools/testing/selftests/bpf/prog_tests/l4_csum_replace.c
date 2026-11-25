// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>
#include "l4_csum_replace.skel.h"

static __u16 tcp_v4_csum(struct iphdr *iph, struct tcphdr *tcp)
{
	__u32 len = ntohs(iph->tot_len) - iph->ihl * 4;
	__u32 sum;

	sum = csum_partial(tcp, len, 0);
	return csum_tcpudp_magic(iph->saddr, iph->daddr, len, IPPROTO_TCP, sum);
}

static __u16 tcp_v6_csum(struct ipv6hdr *ip6h, struct tcphdr *tcp)
{
	__u32 len = ntohs(ip6h->payload_len);
	__u32 sum;

	sum = csum_partial(tcp, len, 0);
	return csum_ipv6_magic(&ip6h->saddr, &ip6h->daddr, len, IPPROTO_TCP, sum);
}

static void run_l4_csum_replace(struct l4_csum_replace *skel)
{
	struct ipv4_packet pkt = pkt_v4;
	char buf[sizeof(struct ipv4_packet)] = {};
	struct iphdr *iph;
	struct tcphdr *tcp;
	__u16 out_csum, exp_csum;
	int err;

	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt,
		.data_size_in = sizeof(pkt),
		.data_out = buf,
		.data_size_out = sizeof(buf),
		.repeat = 1,
	);

	iph = (struct iphdr *)((char *)&pkt + sizeof(struct ethhdr));
	tcp = (struct tcphdr *)((char *)&pkt + sizeof(struct ethhdr) + sizeof(struct iphdr));

	iph->tot_len = htons(sizeof(pkt) - sizeof(struct ethhdr));

	tcp->check = 0;
	tcp->check = tcp_v4_csum(iph, tcp);

	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.l4_csum_replace), &topts);
	if (!ASSERT_OK(err, "test_run"))
		return;
	if (!ASSERT_OK(topts.retval, "retval"))
		return;

	iph = (struct iphdr *)(buf + sizeof(struct ethhdr));
	tcp = (struct tcphdr *)(buf + sizeof(struct ethhdr) + sizeof(struct iphdr));
	ASSERT_EQ(iph->saddr, htonl(0x0a000001), "ip_src");
	ASSERT_EQ(tcp->dest, htons(5001), "tcp_dport");

	out_csum = tcp->check;
	tcp->check = 0;
	exp_csum = tcp_v4_csum(iph, tcp);
	ASSERT_EQ(out_csum, exp_csum, "tcp_csum");
}

static void run_l4_csum_mangled(struct l4_csum_replace *skel)
{
	struct ipv4_packet pkt = pkt_v4;
	char buf[sizeof(struct ipv4_packet)] = {};
	struct iphdr *iph;
	struct tcphdr *tcp;
	int err;

	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt,
		.data_size_in = sizeof(pkt),
		.data_out = buf,
		.data_size_out = sizeof(buf),
		.repeat = 1,
	);

	iph = (struct iphdr *)((char *)&pkt + sizeof(struct ethhdr));
	tcp = (struct tcphdr *)((char *)&pkt + sizeof(struct ethhdr) + sizeof(struct iphdr));
	iph->tot_len = htons(sizeof(pkt) - sizeof(struct ethhdr));

	/* Leave the checksum at zero: MARK_MANGLED_0 must not touch it. */
	tcp->check = 0;

	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.l4_csum_mangled), &topts);
	if (!ASSERT_OK(err, "test_run"))
		return;
	if (!ASSERT_OK(topts.retval, "retval"))
		return;

	tcp = (struct tcphdr *)(buf + sizeof(struct ethhdr) + sizeof(struct iphdr));
	ASSERT_EQ(tcp->dest, htons(5001), "tcp_dport");
	ASSERT_EQ(tcp->check, 0, "tcp_csum_untouched");
}

static void run_l4_csum_mangle_enforce(struct l4_csum_replace *skel)
{
	struct ipv4_packet pkt = pkt_v4;
	char buf[sizeof(struct ipv4_packet)] = {};
	struct iphdr *iph;
	struct tcphdr *tcp;
	int err;

	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt,
		.data_size_in = sizeof(pkt),
		.data_out = buf,
		.data_size_out = sizeof(buf),
		.repeat = 1,
	);

	iph = (struct iphdr *)((char *)&pkt + sizeof(struct ethhdr));
	tcp = (struct tcphdr *)((char *)&pkt + sizeof(struct ethhdr) + sizeof(struct iphdr));
	iph->tot_len = htons(sizeof(pkt) - sizeof(struct ethhdr));

	tcp->check = 0;

	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.l4_csum_mangle_enforce), &topts);
	if (!ASSERT_OK(err, "test_run"))
		return;
	if (!ASSERT_OK(topts.retval, "retval"))
		return;

	tcp = (struct tcphdr *)(buf + sizeof(struct ethhdr) + sizeof(struct iphdr));
	ASSERT_EQ(tcp->dest, 0xffff, "tcp_dport");
	ASSERT_EQ(tcp->check, 0xffff, "tcp_csum_mangled");
}

static void run_l4_csum_ipv6(struct l4_csum_replace *skel)
{
	struct ipv6_packet pkt = pkt_v6;
	char buf[sizeof(struct ipv6_packet)] = {};
	struct ipv6hdr *ip6h;
	struct tcphdr *tcp;
	__u16 out_csum, exp_csum;
	int err;

	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt,
		.data_size_in = sizeof(pkt),
		.data_out = buf,
		.data_size_out = sizeof(buf),
		.repeat = 1,
		.flags = BPF_F_TEST_SKB_CHECKSUM_COMPLETE,
	);

	ip6h = (struct ipv6hdr *)((char *)&pkt + sizeof(struct ethhdr));
	tcp = (struct tcphdr *)((char *)&pkt + sizeof(struct ethhdr) + sizeof(struct ipv6hdr));
	ip6h->payload_len = htons(sizeof(pkt) - sizeof(struct ethhdr) - sizeof(struct ipv6hdr));

	tcp->check = 0;
	tcp->check = tcp_v6_csum(ip6h, tcp);

	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.l4_csum_ipv6), &topts);
	if (!ASSERT_OK(err, "test_run"))
		return;
	if (!ASSERT_OK(topts.retval, "retval"))
		return;

	ip6h = (struct ipv6hdr *)(buf + sizeof(struct ethhdr));
	tcp = (struct tcphdr *)(buf + sizeof(struct ethhdr) + sizeof(struct ipv6hdr));
	ASSERT_EQ(ip6h->saddr.s6_addr32[0], htonl(0x20010db8), "ipv6_src");

	out_csum = tcp->check;
	tcp->check = 0;
	exp_csum = tcp_v6_csum(ip6h, tcp);
	ASSERT_EQ(out_csum, exp_csum, "tcp_csum");
}

void test_l4_csum_replace(void)
{
	struct l4_csum_replace *skel;

	skel = l4_csum_replace__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	if (test__start_subtest("plain"))
		run_l4_csum_replace(skel);
	if (test__start_subtest("mark_mangled_0"))
		run_l4_csum_mangled(skel);
	if (test__start_subtest("mark_mangled_0_enforce"))
		run_l4_csum_mangle_enforce(skel);
	if (test__start_subtest("ipv6"))
		run_l4_csum_ipv6(skel);

	l4_csum_replace__destroy(skel);
}
