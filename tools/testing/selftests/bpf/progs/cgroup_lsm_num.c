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

#define LSM_CGROUP_HOOK(name, hook)		\
	SEC("lsm_cgroup/" #hook)		\
	int BPF_PROG(name) { return 1; }


LSM_CGROUP_HOOK(hook0, socket_create)

LSM_CGROUP_HOOK(hook1, socket_post_create)

LSM_CGROUP_HOOK(hook2, socket_socketpair)

LSM_CGROUP_HOOK(hook3, socket_bind)

LSM_CGROUP_HOOK(hook4, socket_connect)

LSM_CGROUP_HOOK(hook5, socket_listen)

LSM_CGROUP_HOOK(hook6, socket_accept)

LSM_CGROUP_HOOK(hook7, socket_sendmsg)

LSM_CGROUP_HOOK(hook8, socket_recvmsg)

LSM_CGROUP_HOOK(hook9, socket_getsockname)

LSM_CGROUP_HOOK(hook10, socket_getpeername)

LSM_CGROUP_HOOK(hook11, socket_shutdown)

