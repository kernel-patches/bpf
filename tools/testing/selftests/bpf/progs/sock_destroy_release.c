// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

volatile __u64 abort_cookie;

void maybe_abort(struct sock_common *sk, struct seq_file *seq)
{
	__u64 sock_cookie;

	if (!sk)
		return;

	sock_cookie = bpf_get_socket_cookie(sk);
	if (sock_cookie != abort_cookie)
		return;

	bpf_sock_destroy(sk);
	bpf_seq_write(seq, &sock_cookie, sizeof(sock_cookie));
}

SEC("iter/udp")
int abort_udp(struct bpf_iter__udp *ctx)
{
	maybe_abort((struct sock_common *)ctx->udp_sk,
		    ctx->meta->seq);

	return 0;
}

SEC("iter/tcp")
int abort_tcp(struct bpf_iter__tcp *ctx)
{
	maybe_abort((struct sock_common *)ctx->sk_common,
		    ctx->meta->seq);

	return 0;
}

struct bpf_sock sk = {};

SEC("cgroup/sock_release")
int sock_release(struct bpf_sock *ctx)
{
	sk.dst_ip4 = ctx->dst_ip4;
	sk.dst_ip6[0] = ctx->dst_ip6[0];
	sk.dst_ip6[1] = ctx->dst_ip6[1];
	sk.dst_ip6[2] = ctx->dst_ip6[2];
	sk.dst_ip6[3] = ctx->dst_ip6[3];
	sk.dst_port = ctx->dst_port;

	return 1;
}

char _license[] SEC("license") = "GPL";
