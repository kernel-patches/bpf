// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Hengqi Chen */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define SECCOMP_RET_ERRNO	0x00050000U
#define SECCOMP_RET_ALLOW	0x7fff0000U
#define SECCOMP_RET_DATA	0x0000ffffU

const volatile int seccomp_syscall_nr = 0;
const volatile __u32 seccomp_errno = 0;

SEC("seccomp")
int seccomp_prog(struct seccomp_data *ctx)
{
	if (ctx->nr != seccomp_syscall_nr)
		return SECCOMP_RET_ALLOW;

	return SECCOMP_RET_ERRNO | (seccomp_errno & SECCOMP_RET_DATA);
}

char _license[] SEC("license") = "GPL";
