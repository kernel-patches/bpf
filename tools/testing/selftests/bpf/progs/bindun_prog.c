// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */

#include <string.h>

#include <linux/bpf.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <bpf/bpf_helpers.h>

#define DST_REWRITE_PATH	"\0bpf_cgroup_unix_test_rewrite"

SEC("cgroup/bindun")
int bind_un_prog(struct bpf_sock_addr *ctx)
{
	struct bpf_sock *sk;

	sk = ctx->sk;
	if (!sk)
		return 0;

	if (sk->family != AF_UNIX)
		return 0;

	if (ctx->type != SOCK_STREAM && ctx->type != SOCK_DGRAM)
		return 0;

	memcpy(ctx->user_path, DST_REWRITE_PATH, sizeof(DST_REWRITE_PATH));
	ctx->user_addrlen = offsetof(struct sockaddr_un, sun_path) +
			    sizeof(DST_REWRITE_PATH) - 1;

	return 1;
}

char _license[] SEC("license") = "GPL";
