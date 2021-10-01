// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */

#include "test_progs.h"
#include "network_helpers.h"
#include "test_tcp_hdr_options.h"
#include "test_xdp_tcp_hdr_options.skel.h"

struct xdp_exprm_opt {
	__u8 kind;
	__u8 len;
	__u16 magic;
	struct bpf_test_option data;
} __packed;

struct xdp_regular_opt {
	__u8 kind;
	__u8 len;
	struct bpf_test_option data;
} __packed;

struct xdp_test_opt {
	struct xdp_exprm_opt exprm_opt;
	struct xdp_regular_opt regular_opt;
} __packed;

struct xdp_ipv4_packet {
	struct ipv4_packet pkt_v4;
	struct xdp_test_opt test_opt;
} __packed;

struct xdp_ipv6_packet {
	struct ipv6_packet pkt_v6;
	struct xdp_test_opt test_opt;
} __packed;

static __u8 opt_flags = OPTION_MAX_DELACK_MS | OPTION_RAND;
static __u8 exprm_max_delack_ms = 12;
static __u8 regular_max_delack_ms = 21;
static __u8 exprm_rand = 0xfa;
static __u8 regular_rand = 0xce;

static void init_test_opt(struct xdp_test_opt *test_opt,
			  struct test_xdp_tcp_hdr_options *skel)
{
	test_opt->exprm_opt.kind = TCPOPT_EXP;
	/* +1 for kind, +1 for kind-len, +2 for magic, +1 for flags, +1 for
	 * OPTION_MAX_DELACK_MAX, +1 FOR OPTION_RAND
	 */
	test_opt->exprm_opt.len = 3 + TCP_BPF_EXPOPT_BASE_LEN;
	test_opt->exprm_opt.magic = __bpf_htons(skel->rodata->test_magic);
	test_opt->exprm_opt.data.flags = opt_flags;
	test_opt->exprm_opt.data.max_delack_ms = exprm_max_delack_ms;
	test_opt->exprm_opt.data.rand = exprm_rand;

	test_opt->regular_opt.kind = skel->rodata->test_kind;
	/* +1 for kind, +1 for kind-len, +1 for flags, +1 FOR
	 * OPTION_MAX_DELACK_MS, +1 FOR OPTION_RAND
	 */
	test_opt->regular_opt.len = 5;
	test_opt->regular_opt.data.flags = opt_flags;
	test_opt->regular_opt.data.max_delack_ms = regular_max_delack_ms;
	test_opt->regular_opt.data.rand = regular_rand;
}

static void check_opt_out(struct test_xdp_tcp_hdr_options *skel)
{
	struct bpf_test_option *opt_out;
	__u32 duration = 0;

	opt_out = &skel->bss->exprm_opt_out;
	CHECK(opt_out->flags != opt_flags, "exprm flags",
	      "flags = 0x%x", opt_out->flags);
	CHECK(opt_out->max_delack_ms != exprm_max_delack_ms, "exprm max_delack_ms",
	      "max_delack_ms = 0x%x", opt_out->max_delack_ms);
	CHECK(opt_out->rand != exprm_rand, "exprm rand",
	      "rand = 0x%x", opt_out->rand);

	opt_out = &skel->bss->regular_opt_out;
	CHECK(opt_out->flags != opt_flags, "regular flags",
	      "flags = 0x%x", opt_out->flags);
	CHECK(opt_out->max_delack_ms != regular_max_delack_ms, "regular max_delack_ms",
	      "max_delack_ms = 0x%x", opt_out->max_delack_ms);
	CHECK(opt_out->rand != regular_rand, "regular rand",
	      "rand = 0x%x", opt_out->rand);
}

void test_xdp_tcp_hdr_options(void)
{
	int err, prog_fd, prog_err_path_fd, prog_invalid_pkt_fd;
	struct xdp_ipv6_packet ipv6_pkt, invalid_pkt;
	struct test_xdp_tcp_hdr_options *skel;
	struct xdp_ipv4_packet ipv4_pkt;
	struct xdp_test_opt test_opt;
	__u32 duration, retval, size;
	char buf[128];

	/* Load XDP program to introspect */
	skel = test_xdp_tcp_hdr_options__open_and_load();
	if (CHECK(!skel, "skel open and load",
		  "%s skeleton failed\n", __func__))
		return;

	prog_fd = bpf_program__fd(skel->progs._xdp_load_hdr_opt);

	init_test_opt(&test_opt, skel);

	/* Init the packets */
	ipv4_pkt.pkt_v4 = pkt_v4;
	ipv4_pkt.pkt_v4.tcp.doff += 3;
	ipv4_pkt.test_opt = test_opt;

	ipv6_pkt.pkt_v6 = pkt_v6;
	ipv6_pkt.pkt_v6.tcp.doff += 3;
	ipv6_pkt.test_opt = test_opt;

	invalid_pkt.pkt_v6 = pkt_v6;
	/* Set to an offset that will exceed the xdp data_end */
	invalid_pkt.pkt_v6.tcp.doff += 4;
	invalid_pkt.test_opt = test_opt;

	/* Test on ipv4 packet */
	err = bpf_prog_test_run(prog_fd, 1, &ipv4_pkt, sizeof(ipv4_pkt),
				buf, &size, &retval, &duration);
	CHECK(err || retval != XDP_PASS,
	      "xdp_tcp_hdr_options ipv4", "err val %d, retval %d\n",
	      skel->bss->err_val, retval);
	check_opt_out(skel);

	/* Test on ipv6 packet */
	err = bpf_prog_test_run(prog_fd, 1, &ipv6_pkt, sizeof(ipv6_pkt),
				buf, &size, &retval, &duration);
	CHECK(err || retval != XDP_PASS,
	      "xdp_tcp_hdr_options ipv6", "err val %d, retval %d\n",
	      skel->bss->err_val, retval);
	check_opt_out(skel);

	/* Test error paths */
	prog_err_path_fd =
		bpf_program__fd(skel->progs._xdp_load_hdr_opt_err_paths);
	err = bpf_prog_test_run(prog_err_path_fd, 1, &ipv6_pkt, sizeof(ipv6_pkt),
				buf, &size, &retval, &duration);
	CHECK(err || retval != XDP_PASS,
	      "xdp_tcp_hdr_options err_path", "err val %d, retval %d\n",
	      skel->bss->err_val, retval);

	/* Test invalid packet */
	prog_invalid_pkt_fd =
		bpf_program__fd(skel->progs._xdp_load_hdr_opt_invalid_pkt);
	err = bpf_prog_test_run(prog_invalid_pkt_fd, 1, &invalid_pkt,
				sizeof(invalid_pkt), buf, &size, &retval,
				&duration);
	CHECK(err || retval != XDP_PASS,
	      "xdp_tcp_hdr_options invalid_pkt", "err val %d, retval %d\n",
	      skel->bss->err_val, retval);

	test_xdp_tcp_hdr_options__destroy(skel);
}
