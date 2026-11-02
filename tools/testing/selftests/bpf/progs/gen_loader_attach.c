// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Isovalent */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("lsm/file_open")
int lsm_open(void *ctx)
{
	return 0;
}

SEC("lsm/file_permission")
int lsm_perm(void *ctx)
{
	return 0;
}

SEC("?socket")
int socket(void *ctx)
{
	return 0;
}

SEC("?fentry/security_inode_getattr")
int fentry(void *ctx)
{
	return 0;
}

SEC("?fexit/security_inode_getattr")
int fexit(void *ctx)
{
	return 0;
}

SEC("?fmod_ret/security_inode_getattr")
int fmod_ret(void *ctx)
{
	return 0;
}

SEC("?tp_btf/sys_enter")
int tp_btf(void *ctx)
{
	return 0;
}

char _license[] SEC("license") = "GPL";
