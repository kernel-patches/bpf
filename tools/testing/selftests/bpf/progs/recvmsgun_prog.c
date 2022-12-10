// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */

#include <string.h>

#include <linux/bpf.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <bpf/bpf_helpers.h>

#define SERVUN_PATH		"\0bpf_cgroup_unix_test"

SEC("cgroup/recvmsgun")
int recvmsgun_prog(struct bpf_sock_addr *ctx)
{
	struct bpf_sock *sk;

	sk = ctx->sk;
	if (!sk)
		return 1;

	if (sk->family != AF_UNIX)
		return 1;

	if (ctx->type != SOCK_STREAM && ctx->type != SOCK_DGRAM)
		return 1;

	memcpy(ctx->user_path, SERVUN_PATH, sizeof(SERVUN_PATH));
	ctx->user_addrlen = offsetof(struct sockaddr_un, sun_path) +
			    sizeof(SERVUN_PATH) - 1;

	return 1;
}

char _license[] SEC("license") = "GPL";
