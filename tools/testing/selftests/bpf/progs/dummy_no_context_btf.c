// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* A dummy program that does not reference context types in it's BTF */
SEC("tc")
__u32 dummy_prog(void *ctx)
{
	return 0;
}

char _license[] SEC("license") = "GPL";
