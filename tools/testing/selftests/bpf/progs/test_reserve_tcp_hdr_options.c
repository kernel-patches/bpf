// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 ByteDance Inc. */

#include <stddef.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/socket.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#define BPF_PROG_TEST_TCP_HDR_OPTIONS
#include "test_tcp_hdr_options.h"

unsigned int nr_err_reserve = 0;
unsigned int nr_nospc = 0;

static bool skops_current_mss(const struct bpf_sock_ops *skops)
{
	return skops->args[0] == BPF_WRITE_HDR_TCP_CURRENT_MSS;
}

static int handle_hdr_opt_len(struct bpf_sock_ops *skops)
{
	int err;

	if (skops_current_mss(skops)) {
		err = bpf_reserve_hdr_opt(skops, 4, 0);
		if (err) {
			nr_err_reserve++;
			RET_CG_ERR(err);
		}
	} else {
		err = bpf_reserve_hdr_opt(skops, 8, 0);
		if (err) {
			if (err == -ENOSPC) {
				nr_nospc++;
			} else {
				nr_err_reserve++;
				RET_CG_ERR(err);
			}
		}
	}

	return CG_OK;
}

SEC("sockops")
int reserve_tcp_hdr_options(struct bpf_sock_ops *skops)
{
	switch (skops->op) {
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		bpf_sock_ops_cb_flags_set(skops,
					  skops->bpf_sock_ops_cb_flags |
					  BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
		break;
	case BPF_SOCK_OPS_HDR_OPT_LEN_CB:
		return handle_hdr_opt_len(skops);
	case BPF_SOCK_OPS_WRITE_HDR_OPT_CB:
		break;
	}

	return CG_OK;
}

char _license[] SEC("license") = "GPL";
