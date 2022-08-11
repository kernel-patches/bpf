// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include <network_helpers.h>
#include "test_parse_tcp_hdr_opt.skel.h"
#include "test_parse_tcp_hdr_opt_dynptr.skel.h"
#include "test_tcp_hdr_options.h"

struct test_pkt {
	struct ipv6_packet pk6_v6;
	u8 options[16];
} __packed;

struct test_pkt pkt = {
	.pk6_v6.eth.h_proto = __bpf_constant_htons(ETH_P_IPV6),
	.pk6_v6.iph.nexthdr = IPPROTO_TCP,
	.pk6_v6.iph.payload_len = __bpf_constant_htons(MAGIC_BYTES),
	.pk6_v6.tcp.urg_ptr = 123,
	.pk6_v6.tcp.doff = 9, /* 16 bytes of options */

	.options = {
		TCPOPT_MSS, 4, 0x05, 0xB4, TCPOPT_NOP, TCPOPT_NOP,
		0, 6, 0, 0, 0, 9, TCPOPT_EOL
	},
};

static void test_parsing(bool use_dynptr)
{
	char buf[128];
	struct bpf_program *prog;
	void *skel_ptr;
	int err;

	LIBBPF_OPTS(bpf_test_run_opts, topts,
		    .data_in = &pkt,
		    .data_size_in = sizeof(pkt),
		    .data_out = buf,
		    .data_size_out = sizeof(buf),
		    .repeat = 3,
	);

	if (use_dynptr) {
		struct test_parse_tcp_hdr_opt_dynptr *skel;

		skel = test_parse_tcp_hdr_opt_dynptr__open_and_load();
		if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
			return;

		pkt.options[6] = skel->rodata->tcp_hdr_opt_kind_tpr;
		prog = skel->progs.xdp_ingress_v6;
		skel_ptr = skel;
	} else {
		struct test_parse_tcp_hdr_opt *skel;

		skel = test_parse_tcp_hdr_opt__open_and_load();
		if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
			return;

		pkt.options[6] = skel->rodata->tcp_hdr_opt_kind_tpr;
		prog = skel->progs.xdp_ingress_v6;
		skel_ptr = skel;
	}

	err = bpf_prog_test_run_opts(bpf_program__fd(prog), &topts);
	ASSERT_OK(err, "ipv6 test_run");
	ASSERT_EQ(topts.retval, XDP_PASS, "ipv6 test_run retval");

	if (use_dynptr) {
		struct test_parse_tcp_hdr_opt_dynptr *skel = skel_ptr;

		ASSERT_EQ(skel->bss->server_id, 0x9000000, "server id");
		test_parse_tcp_hdr_opt_dynptr__destroy(skel);
	} else {
		struct test_parse_tcp_hdr_opt *skel = skel_ptr;

		ASSERT_EQ(skel->bss->server_id, 0x9000000, "server id");
		test_parse_tcp_hdr_opt__destroy(skel);
	}
}

void test_parse_tcp_hdr_opt(void)
{
	test_parsing(false);
	test_parsing(true);
}
