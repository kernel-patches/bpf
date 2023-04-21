// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"

#include <string.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "bpf_kfuncs.h"

#ifndef AF_UNIX
#define AF_UNIX 1
#endif

#define SERVUN_PATH		"\0bpf_cgroup_unix_test"

void *bpf_cast_to_kern_ctx(void *) __ksym;

SEC("cgroup/recvmsgun")
int recvmsgun_prog(struct bpf_sock_addr *ctx)
{
	struct bpf_sock *sk = ctx->sk;
	struct bpf_sock_addr_kern *sa_kern = bpf_cast_to_kern_ctx(ctx);
	struct sockaddr_un *sa_kern_unaddr;
	struct sockaddr_un unaddr = {
		.sun_family = AF_UNIX,
	};
	__u32 unaddrlen = offsetof(struct sockaddr_un, sun_path) +
			  sizeof(SERVUN_PATH) - 1;
	int ret;

	if (!sk)
		return 1;

	if (sk->family != AF_UNIX)
		return 1;

	if (ctx->type != SOCK_STREAM && ctx->type != SOCK_DGRAM)
		return 1;

	memcpy(unaddr.sun_path, SERVUN_PATH, sizeof(SERVUN_PATH) - 1);

	ret = bpf_sock_addr_set(sa_kern, (struct sockaddr *) &unaddr, unaddrlen);
	if (ret)
		return 1;

	if (sa_kern->uaddrlen != unaddrlen)
		return 1;

	sa_kern_unaddr = bpf_rdonly_cast(sa_kern->uaddr,
					 bpf_core_type_id_kernel(struct sockaddr_un));
	if (memcmp(sa_kern_unaddr->sun_path, SERVUN_PATH,
		   sizeof(SERVUN_PATH) - 1) != 0)
		return 1;

	return 1;
}

char _license[] SEC("license") = "GPL";
