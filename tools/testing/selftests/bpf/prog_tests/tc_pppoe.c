// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 ThisSeanZhang */

#include <arpa/inet.h>
#include <test_progs.h>
#include "tc_pppoe.skel.h"

/* Ethernet + IPv4 + TCP, 54 bytes in total. */
static const __u8 ip4_pkt[] = {
	/* Ethernet header. */
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
	0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	0x08, 0x00,
	/* IPv4 header. */
	0x45, 0x00, 0x00, 0x28,
	0x12, 0x34, 0x40, 0x00,
	0x40, 0x06, 0x00, 0x00,
	0xc0, 0xa8, 0x01, 0x01,
	0xc0, 0xa8, 0x01, 0x02,
	/* TCP header. */
	0x00, 0x50, 0x1f, 0x90,
	0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x00,
	0x50, 0x02, 0x10, 0x00,
	0x00, 0x00, 0x00, 0x00,
};

/* Ethernet + IPv6 + TCP, 74 bytes in total. */
static const __u8 ip6_pkt[] = {
	/* Ethernet header. */
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
	0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	0x86, 0xdd,
	/* IPv6 header. */
	0x60, 0x00, 0x00, 0x00,
	0x00, 0x14, 0x06, 0x40,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	/* TCP header. */
	0x00, 0x50, 0x1f, 0x90,
	0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x00,
	0x50, 0x02, 0x10, 0x00,
	0x00, 0x00, 0x00, 0x00,
};

#define PPP_SES_HLEN	8
#define TC_ACT_SHOT	2

static int run_prog(int prog_fd, const void *data_in, __u32 size_in,
		    void *data_out, __u32 size_out, __u32 *retval,
		    __u32 *size_out_actual)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		    .data_in = (void *)data_in,
		    .data_size_in = size_in,
		    .data_out = data_out,
		    .data_size_out = size_out,
	);
	int ret;

	ret = bpf_prog_test_run_opts(prog_fd, &opts);
	if (!ret && retval)
		*retval = opts.retval;
	if (!ret && size_out_actual)
		*size_out_actual = opts.data_size_out;

	return ret;
}

static void test_encap_decap(struct tc_pppoe *skel, const char *subtest,
			     const __u8 *pkt, __u32 pkt_len, int ethertype,
			     __u8 ppp_proto)
{
	__u8 encap_pkt[128];
	__u8 decap_pkt[128];
	__u32 retval, out_len;
	int ret;

	if (!test__start_subtest(subtest))
		return;

	skel->bss->encap_proto = 0;
	ret = run_prog(bpf_program__fd(skel->progs.tc_pppoe_encap),
		       pkt, pkt_len, encap_pkt, sizeof(encap_pkt),
		       &retval, &out_len);
	ASSERT_OK(ret, "encap test_run");
	ASSERT_OK(retval, "encap retval");
	ASSERT_EQ(out_len, pkt_len + PPP_SES_HLEN, "encap pkt len");
	ASSERT_EQ(skel->bss->encap_proto, htons(0x8864),
		  "encap skb protocol");

	/* Ethernet header, with the ethertype changed to PPPoE session. */
	ASSERT_EQ(encap_pkt[12], 0x88, "encap eth h_proto");
	ASSERT_EQ(encap_pkt[13], 0x64, "encap eth h_proto");
	/*
	 * PPPoE session header: ver/type/code, session id, length and
	 * PPP protocol.
	 */
	ASSERT_EQ(encap_pkt[14], 0x11, "encap pppoe ver/type");
	ASSERT_EQ(encap_pkt[15], 0x00, "encap pppoe code");
	ASSERT_EQ(encap_pkt[16], 0xde, "encap pppoe sid");
	ASSERT_EQ(encap_pkt[17], 0xad, "encap pppoe sid");
	ASSERT_EQ(encap_pkt[18], 0x00, "encap pppoe length");
	ASSERT_EQ(encap_pkt[19], pkt_len - 14 + 2, "encap pppoe length");
	ASSERT_EQ(encap_pkt[20], 0x00, "encap ppp proto");
	ASSERT_EQ(encap_pkt[21], ppp_proto, "encap ppp proto");
	/*
	 * The original packet must be shifted unchanged behind the
	 * new header.
	 */
	ASSERT_MEMEQ(encap_pkt + 14 + PPP_SES_HLEN, pkt + 14,
		     pkt_len - 14, "encap payload");

	skel->bss->decap_proto = 0;
	ret = run_prog(bpf_program__fd(skel->progs.tc_pppoe_decap),
		       encap_pkt, pkt_len + PPP_SES_HLEN, decap_pkt,
		       sizeof(decap_pkt), &retval, &out_len);
	ASSERT_OK(ret, "decap test_run");
	ASSERT_OK(retval, "decap retval");
	ASSERT_EQ(out_len, pkt_len, "decap pkt len");
	ASSERT_EQ(skel->bss->decap_proto, ethertype, "decap skb protocol");
	ASSERT_MEMEQ(decap_pkt, pkt, pkt_len, "decap packet");
}

static void test_reject(struct tc_pppoe *skel, int case_id,
			const void *data_in, __u32 size_in, const char *name)
{
	__u8 out[128];
	__u32 retval = 0;
	int ret;

	if (!test__start_subtest(name))
		return;

	skel->bss->reject_case = case_id;
	skel->bss->reject_unexpected = 0;
	ret = run_prog(bpf_program__fd(skel->progs.tc_pppoe_reject),
		       data_in, size_in, out, sizeof(out), &retval, NULL);
	ASSERT_OK(ret, "reject test_run");
	ASSERT_EQ(retval, TC_ACT_SHOT, "helper rejected the call");
	ASSERT_EQ(skel->bss->reject_unexpected, 0, "no unexpected success");
}

static void test_decap_reject_input(struct tc_pppoe *skel,
				    const __u8 *pkt, __u32 pkt_len,
				    const char *subtest)
{
	__u8 out[128];
	__u32 retval = 0;
	int ret;

	if (!test__start_subtest(subtest))
		return;

	skel->bss->decap_proto = 0;
	ret = run_prog(bpf_program__fd(skel->progs.tc_pppoe_decap),
		       pkt, pkt_len, out, sizeof(out), &retval, NULL);
	ASSERT_OK(ret, "decap reject test_run");
	ASSERT_EQ(retval, TC_ACT_SHOT, "helper rejected the call");
	ASSERT_EQ(skel->bss->decap_proto, 0, "skb protocol unchanged");
}

void test_tc_pppoe(void)
{
	/*
	 * A PPPoE packet whose PPP protocol is neither IPv4 nor IPv6:
	 * IP control protocol (0x8021) in this case.
	 */
	static const __u8 bad_ppp_pkt[] = {
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x88, 0x64,
		0x11, 0x00, 0x00, 0x00, 0x00, 0x28, 0x80, 0x21,
		0x45, 0x00, 0x00, 0x28,
		0x12, 0x34, 0x40, 0x00,
		0x40, 0x06, 0x00, 0x00,
		0xc0, 0xa8, 0x01, 0x01,
		0xc0, 0xa8, 0x01, 0x02,
		0x00, 0x50, 0x1f, 0x90,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x50, 0x02, 0x10, 0x00,
		0x00, 0x00, 0x00, 0x00,
	};
	/*
	 * A PPPoE packet whose payload is too short to still contain a
	 * full IP header after decapsulation.
	 */
	static const __u8 truncated_pkt[] = {
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x88, 0x64,
		0x11, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x21,
		0x45, 0x00,
	};
	/* Non-PPPoE IPv4 packet whose bytes 20/21 decode as PPP_IP. */
	static const __u8 fake_ppp_pkt[] = {
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x08, 0x00,
		0x45, 0x00, 0x00, 0x28,
		0x12, 0x34, 0x00, 0x21,
		0x40, 0x06, 0x00, 0x00,
		0xc0, 0xa8, 0x01, 0x01,
		0xc0, 0xa8, 0x01, 0x02,
		0x00, 0x50, 0x1f, 0x90,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x50, 0x02, 0x10, 0x00,
		0x00, 0x00, 0x00, 0x00,
	};
	__u8 encap_pkt[128];
	struct tc_pppoe *skel;
	__u32 retval, out_len;

	skel = tc_pppoe__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel open_and_load"))
		return;

	test_encap_decap(skel, "encap-decap-v4", ip4_pkt, sizeof(ip4_pkt),
			 htons(0x0800), 0x21);
	test_encap_decap(skel, "encap-decap-v6", ip6_pkt, sizeof(ip6_pkt),
			 htons(0x86dd), 0x57);

	test_decap_reject_input(skel, bad_ppp_pkt, sizeof(bad_ppp_pkt),
				"decap-bad-ppp-proto");
	test_decap_reject_input(skel, truncated_pkt, sizeof(truncated_pkt),
				"decap-truncated");
	test_reject(skel, 6, fake_ppp_pkt, sizeof(fake_ppp_pkt),
		    "reject-decap-fake-ppp-proto");

	/*
	 * Encapsulate a v4 packet once more to get a PPPoE packet as
	 * input for the "decap without the flag" rejection case.
	 */
	ASSERT_OK(run_prog(bpf_program__fd(skel->progs.tc_pppoe_encap),
			   ip4_pkt, sizeof(ip4_pkt), encap_pkt,
			   sizeof(encap_pkt), &retval, &out_len),
		  "encap v4 for reject input");

	test_reject(skel, 1, ip4_pkt, sizeof(ip4_pkt), "reject-encap-len");
	test_reject(skel, 2, ip4_pkt, sizeof(ip4_pkt), "reject-encap-mode");
	test_reject(skel, 3, ip4_pkt, sizeof(ip4_pkt), "reject-encap-shrink");
	test_reject(skel, 4, ip4_pkt, sizeof(ip4_pkt), "reject-flag-mix");
	test_reject(skel, 5, encap_pkt, sizeof(ip4_pkt) + PPP_SES_HLEN,
		    "reject-decap-no-flag");
	test_reject(skel, 6, ip4_pkt, sizeof(ip4_pkt),
		    "reject-decap-non-pppoe");

	tc_pppoe__destroy(skel);
}
