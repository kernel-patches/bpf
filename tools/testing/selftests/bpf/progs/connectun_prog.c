// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2018 Facebook

#include <string.h>

#include <linux/stddef.h>
#include <linux/bpf.h>
#include <linux/if.h>
#include <errno.h>

#include <bpf/bpf_helpers.h>

#define DST_REWRITE_PATH	"/tmp/bpf_cgroup_unix_test_rewrite"

SEC("cgroup/connectun")
int connect_un_prog(struct bpf_sock_addr *ctx)
{
	if (ctx->type != SOCK_STREAM && ctx->type != SOCK_DGRAM)
		return 0;

	/* Rewrite destination. */
	memcpy(ctx->user_path, DST_REWRITE_PATH, sizeof(DST_REWRITE_PATH));

	return 1;
}

char _license[] SEC("license") = "GPL";
