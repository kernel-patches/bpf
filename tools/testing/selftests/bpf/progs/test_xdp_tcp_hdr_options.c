// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#define BPF_PROG_TEST_TCP_HDR_OPTIONS
#include "test_tcp_hdr_options.h"

struct bpf_test_option regular_opt_out;
struct bpf_test_option exprm_opt_out;

const __u16 test_magic = 0xeB9F;
const __u8 test_kind = 0xB9;

int err_val = 0;

static void copy_opt_to_out(struct bpf_test_option *test_option, __u8 *data)
{
	test_option->flags = data[0];
	test_option->max_delack_ms = data[1];
	test_option->rand = data[2];
}

static int parse_xdp(struct xdp_md *xdp, __u64 *out_flags)
{
	void *data_end = (void *)(long)xdp->data_end;
	__u64 tcphdr_offset = 0, nh_off;
	void *data = (void *)(long)xdp->data;
	struct ethhdr *eth = data;
	int ret;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end) {
		err_val = 1;
		return XDP_DROP;
	}

	/* Calculate the offset to the tcp hdr */
	if (eth->h_proto == __bpf_constant_htons(ETH_P_IPV6)) {
		tcphdr_offset = sizeof(struct ethhdr) +
			sizeof(struct ipv6hdr);
	} else if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		tcphdr_offset = sizeof(struct ethhdr) +
			sizeof(struct iphdr);
	} else {
		err_val = 2;
		return XDP_DROP;
	}

	*out_flags = tcphdr_offset << BPF_LOAD_HDR_OPT_TCP_OFFSET_SHIFT;

	return XDP_PASS;
}

SEC("xdp")
int _xdp_load_hdr_opt(struct xdp_md *xdp)
{
	struct tcp_exprm_opt exprm_opt = { 0 };
	struct tcp_opt regular_opt = { 0 };
	__u64 flags = 0;
	int ret;

	ret = parse_xdp(xdp, &flags);
	if (ret != XDP_PASS)
		return ret;

	/* Test TCPOPT_EXP */
	exprm_opt.kind = TCPOPT_EXP;
	exprm_opt.len = 4;
	exprm_opt.magic = __bpf_htons(test_magic);
	ret = bpf_load_hdr_opt(xdp, &exprm_opt,
			       sizeof(exprm_opt), flags);
	if (ret < 0) {
		err_val = 3;
		return XDP_DROP;
	}

	copy_opt_to_out(&exprm_opt_out, exprm_opt.data);

	/* Test non-TCP_OPT_EXP */
	regular_opt.kind = test_kind;
	ret = bpf_load_hdr_opt(xdp, &regular_opt,
			       sizeof(regular_opt), flags);
	if (ret < 0) {
		err_val = 4;
		return XDP_DROP;
	}

	copy_opt_to_out(&regular_opt_out, regular_opt.data);

	return XDP_PASS;
}

SEC("xdp")
int _xdp_load_hdr_opt_err_paths(struct xdp_md *xdp)
{
	struct tcp_exprm_opt exprm_opt = { 0 };
	struct tcp_opt regular_opt = { 0 };
	__u64 flags = 0;
	int ret;

	ret = parse_xdp(xdp, &flags);
	if (ret != XDP_PASS)
		return ret;

	/* Test TCPOPT_EXP with invalid magic */
	exprm_opt.kind = TCPOPT_EXP;
	exprm_opt.len = 4;
	exprm_opt.magic = __bpf_htons(test_magic + 1);
	ret = bpf_load_hdr_opt(xdp, &exprm_opt,
			       sizeof(exprm_opt), flags);
	if (ret != -ENOMSG) {
		err_val = 3;
		return XDP_DROP;
	}

	/* Test TCPOPT_EXP with 0 magic */
	exprm_opt.magic = 0;
	ret = bpf_load_hdr_opt(xdp, &exprm_opt,
			       sizeof(exprm_opt), flags);
	if (ret != -ENOMSG) {
		err_val = 4;
		return XDP_DROP;
	}

	exprm_opt.magic = __bpf_htons(test_magic);

	/* Test TCPOPT_EXP with invalid kind length */
	exprm_opt.len = 5;
	ret = bpf_load_hdr_opt(xdp, &exprm_opt,
			       sizeof(exprm_opt), flags);
	if (ret != -EINVAL) {
		err_val = 5;
		return XDP_DROP;
	}

	/* Test that non-existent option is not found */
	regular_opt.kind = test_kind + 1;
	ret = bpf_load_hdr_opt(xdp, &regular_opt,
			       sizeof(regular_opt), flags);
	if (ret != -ENOMSG) {
		err_val = 6;
		return XDP_DROP;
	}

	/* Test invalid flags */
	regular_opt.kind = test_kind;
	ret = bpf_load_hdr_opt(xdp, &regular_opt, sizeof(regular_opt),
			       flags | BPF_LOAD_HDR_OPT_TCP_SYN);
	if (ret != -EINVAL) {
		err_val = 7;
		return XDP_DROP;
	}

	/* Test non-TCP_OPT_EXP with option size smaller than kind len */
	ret = bpf_load_hdr_opt(xdp, &regular_opt,
			       sizeof(regular_opt) - 2, flags);
	if (ret != -ENOSPC) {
		err_val = 8;
		return XDP_DROP;
	}

	return XDP_PASS;
}

SEC("xdp")
int _xdp_load_hdr_opt_invalid_pkt(struct xdp_md *xdp)
{
	struct tcp_exprm_opt exprm_opt = { 0 };
	__u64 flags = 0;
	int ret;

	ret = parse_xdp(xdp, &flags);
	if (ret != XDP_PASS)
		return ret;

	exprm_opt.kind = TCPOPT_EXP;
	exprm_opt.len = 4;
	exprm_opt.magic = __bpf_htons(test_magic);
	ret = bpf_load_hdr_opt(xdp, &exprm_opt,
			       sizeof(exprm_opt), flags);
	if (ret != -EINVAL) {
		err_val = 3;
		return XDP_DROP;
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
