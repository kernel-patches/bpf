// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Isovalent */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "ksock_common.h"

char send_data[11] = "dummy data";

SEC("lsm.s/socket_sendmsg")
__description("bpf_ksock_send is rejected from socket_sendmsg LSM hook")
__failure __msg("calling kernel function bpf_ksock_send is not allowed")
int BPF_PROG(socket_sendmsg_ksock_send, struct socket *sock, struct msghdr *msg,
	     int size, int ret)
{
	struct __ksock_ctx_value *v;
	struct bpf_ksock *ks;

	v = ksock_ctx_value_lookup();
	if (!v)
		return ret;

	ks = bpf_kptr_xchg(&v->ctx, NULL);
	if (!ks)
		return ret;

	bpf_ksock_send(ks, send_data, sizeof(send_data));
	bpf_ksock_release(ks);

	return ret;
}

SEC("lsm.s/socket_sendmsg")
__description("bpf_ksock operations other than send are allowed from socket_sendmsg LSM hook")
__success
int BPF_PROG(socket_sendmsg_ksock_allowed, struct socket *sock,
	     struct msghdr *msg, int size, int ret)
{
	struct bpf_ksock *ks;

	ks = ksock_ctx_get();
	if (!ks)
		return ret;

	bpf_ksock_release(ks);
	return ret;
}

SEC("lsm.s/socket_sendmsg")
__description("bpf_ksock_connect is rejected from socket_sendmsg LSM hook")
__failure __msg("calling kernel function bpf_ksock_connect is not allowed")
int BPF_PROG(socket_sendmsg_ksock_connect, struct socket *sock,
	     struct msghdr *msg, int size, int ret)
{
	struct bpf_ksock *ks;
	union bpf_ksock_addr addr = {};

	ks = ksock_ctx_get();
	if (!ks)
		return ret;

	bpf_ksock_connect(ks, &addr, sizeof(addr));
	bpf_ksock_release(ks);
	return ret;
}

SEC("lsm.s/socket_connect")
__description("bpf_ksock_connect is rejected from socket_connect LSM hook")
__failure __msg("calling kernel function bpf_ksock_connect is not allowed")
int BPF_PROG(socket_connect_ksock_connect, struct socket *sock, struct sockaddr *address,
	     int addrlen, int ret)
{
	struct __ksock_ctx_value *v;
	union bpf_ksock_addr addr = {};
	struct bpf_ksock *ks;

	v = ksock_ctx_value_lookup();
	if (!v)
		return ret;

	ks = bpf_kptr_xchg(&v->ctx, NULL);
	if (!ks)
		return ret;

	bpf_ksock_connect(ks, &addr, sizeof(addr));
	bpf_ksock_release(ks);

	return ret;
}

SEC("lsm.s/socket_connect")
__description("bpf_ksock operations other than connect are allowed from socket_connect LSM hook")
__success
int BPF_PROG(socket_connect_ksock_allowed, struct socket *sock,
	     struct sockaddr *address, int addrlen, int ret)
{
	struct bpf_ksock *ks;

	ks = ksock_ctx_get();
	if (!ks)
		return ret;

	bpf_ksock_send(ks, send_data, sizeof(send_data));
	bpf_ksock_release(ks);

	return ret;
}

char __license[] SEC("license") = "GPL";
