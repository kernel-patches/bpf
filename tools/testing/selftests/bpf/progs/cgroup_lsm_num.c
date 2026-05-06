// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Orange */

/*
 * 12 LSM programs with lsm_cgroup attachment type, each on a distinct LSM
 * hook. Used by prog_tests/cgroup_lsm_num.c to verify that the kernel
 * enforces the CONFIG_CGROUP_LSM_NUM limit on unique per-cgroup LSM hook
 * slots. With CONFIG_CGROUP_LSM_NUM set to 10, 10 shall be attached and 2
 * rejected.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

SEC("lsm_cgroup/socket_create")
int BPF_PROG(hook0, int family, int type, int protocol, int kern)
{
	return 1;
}

SEC("lsm_cgroup/socket_post_create")
int BPF_PROG(hook1, struct socket *sock, int family, int type,
	     int protocol, int kern)
{
	return 1;
}

SEC("lsm_cgroup/socket_socketpair")
int BPF_PROG(hook2, struct socket *socka, struct socket *sockb)
{
	return 1;
}

SEC("lsm_cgroup/socket_bind")
int BPF_PROG(hook3, struct socket *sock, struct sockaddr *address,
	     int addrlen)
{
	return 1;
}

SEC("lsm_cgroup/socket_connect")
int BPF_PROG(hook4, struct socket *sock, struct sockaddr *address,
	     int addrlen)
{
	return 1;
}

SEC("lsm_cgroup/socket_listen")
int BPF_PROG(hook5, struct socket *sock, int backlog)
{
	return 1;
}

SEC("lsm_cgroup/socket_accept")
int BPF_PROG(hook6, struct socket *sock, struct socket *newsock)
{
	return 1;
}

SEC("lsm_cgroup/socket_sendmsg")
int BPF_PROG(hook7, struct socket *sock, struct msghdr *msg, int size)
{
	return 1;
}

SEC("lsm_cgroup/socket_recvmsg")
int BPF_PROG(hook8, struct socket *sock, struct msghdr *msg, int size,
	     int flags)
{
	return 1;
}

SEC("lsm_cgroup/socket_getsockname")
int BPF_PROG(hook9, struct socket *sock)
{
	return 1;
}

SEC("lsm_cgroup/socket_getpeername")
int BPF_PROG(hook10, struct socket *sock)
{
	return 1;
}

SEC("lsm_cgroup/socket_shutdown")
int BPF_PROG(hook11, struct socket *sock, int how)
{
	return 1;
}
