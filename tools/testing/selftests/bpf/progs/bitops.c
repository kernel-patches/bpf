// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "bpf_experimental.h"

__u64 in_x;
__u64 in_s;

__u64 out;

SEC("?syscall")
int bitops_clz64(void *ctx)
{
	out = bpf_clz64(in_x);
	return 0;
}

SEC("?syscall")
int bitops_ctz64(void *ctx)
{
	out = bpf_ctz64(in_x);
	return 0;
}

SEC("?syscall")
int bitops_ffs64(void *ctx)
{
	out = bpf_ffs64(in_x);
	return 0;
}

SEC("?syscall")
int bitops_fls64(void *ctx)
{
	out = bpf_fls64(in_x);
	return 0;
}

SEC("?syscall")
int bitops_bitrev(void *ctx)
{
	out = bpf_bitrev64(in_x);
	return 0;
}

SEC("?syscall")
int bitops_popcnt(void *ctx)
{
	out = bpf_popcnt64(in_x);
	return 0;
}

SEC("?syscall")
int bitops_rol64(void *ctx)
{
	out = bpf_rol64(in_x, in_s);
	return 0;
}

SEC("?syscall")
int bitops_ror64(void *ctx)
{
	out = bpf_ror64(in_x, in_s);
	return 0;
}

char _license[] SEC("license") = "GPL";
