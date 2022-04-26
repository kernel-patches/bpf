// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#ifndef AF_PACKET
#define AF_PACKET 17
#endif

#ifndef AF_UNIX
#define AF_UNIX 1
#endif

#ifndef EPERM
#define EPERM 1
#endif

int called_socket_post_create;
int called_socket_post_create2;
int called_socket_bind;
int called_socket_bind2;
int called_socket_alloc;
int called_socket_clone;

static __always_inline int real_create(struct socket *sock, int family,
				       int protocol)
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

/* __cgroup_bpf_run_lsm_socket */
SEC("lsm_cgroup/socket_post_create")
int BPF_PROG(socket_post_create, struct socket *sock, int family,
	     int type, int protocol, int kern)
{
	called_socket_post_create++;
	return real_create(sock, family, protocol);
}

/* __cgroup_bpf_run_lsm_socket */
SEC("lsm_cgroup/socket_post_create")
int BPF_PROG(socket_post_create2, struct socket *sock, int family,
	     int type, int protocol, int kern)
{
	called_socket_post_create2++;
	return real_create(sock, family, protocol);
}

static __always_inline int real_bind(struct socket *sock,
				     struct sockaddr *address,
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

/* __cgroup_bpf_run_lsm_socket */
SEC("lsm_cgroup/socket_bind")
int BPF_PROG(socket_bind, struct socket *sock, struct sockaddr *address,
	     int addrlen)
{
	called_socket_bind++;
	return real_bind(sock, address, addrlen);
}

/* __cgroup_bpf_run_lsm_socket */
SEC("lsm_cgroup/socket_bind")
int BPF_PROG(socket_bind2, struct socket *sock, struct sockaddr *address,
	     int addrlen)
{
	called_socket_bind2++;
	return real_bind(sock, address, addrlen);
}

/* __cgroup_bpf_run_lsm_current (via bpf_lsm_current_hooks) */
SEC("lsm_cgroup/sk_alloc_security")
int BPF_PROG(socket_alloc, struct sock *sk, int family, gfp_t priority)
{
	called_socket_alloc++;
	if (family == AF_UNIX)
		return 0; /* EPERM */
	return 1;
}

/* __cgroup_bpf_run_lsm_sock */
SEC("lsm_cgroup/inet_csk_clone")
int BPF_PROG(socket_clone, struct sock *newsk, const struct request_sock *req)
{
	called_socket_clone++;

	if (!newsk)
		return 1;

	/* Accepted request sockets get a different priority.
	 */
	newsk->sk_priority = 234;
	return 1;
}
