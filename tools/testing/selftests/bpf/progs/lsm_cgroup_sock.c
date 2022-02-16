// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#ifndef AF_PACKET
#define AF_PACKET 17
#endif

#ifndef EPERM
#define EPERM 1
#endif

SEC("lsm_cgroup_sock/socket_post_create")
int BPF_PROG(socket_post_create, struct socket *sock, int family,
	     int type, int protocol, int kern)
{
	struct sock *sk;

	/* Reject non-tx-only AF_PACKET.
	 */
	if (family == AF_PACKET && protocol != 0)
		return 0; /* EPERM */

	sk = sock->sk;
	if (!sk)
		return 1;

	/* The rest of the sockets get default policy.
	 */
	sk->sk_priority = 123;
	return 1;
}

SEC("lsm_cgroup_sock/socket_bind")
int BPF_PROG(socket_bind, struct socket *sock, struct sockaddr *address,
	     int addrlen)
{
	struct sockaddr_ll sa = {};

	if (sock->sk->__sk_common.skc_family != AF_PACKET)
		return 1;

	if (sock->sk->sk_kern_sock)
		return 1;

	bpf_probe_read_kernel(&sa, sizeof(sa), address);
	if (sa.sll_protocol)
		return 0; /* EPERM */

	return 1;
}
