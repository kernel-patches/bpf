// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_experimental.h"

SEC("?freplace")
int extension(struct __sk_buff *ctx)
{
	return 0;
}

SEC("?freplace")
int throwing_extension(struct __sk_buff *ctx)
{
	throw;
}

SEC("?fexit")
int pfexit(void *ctx)
{
	return 0;
}

SEC("?fexit")
int throwing_fexit(void *ctx)
{
	throw;
}

SEC("?fmod_ret")
int pfmod_ret(void *ctx)
{
	return 1;
}

SEC("?fmod_ret")
int throwing_fmod_ret(void *ctx)
{
	throw;
}

char _license[] SEC("license") = "GPL";
