// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

SEC("fexit/bpf_testmod_loop_test")
int test_kmod_btfs(void *ctx)
{
	return 0;
}

DEFINE_KMOD_BTFS(_needed_kmods) = { "bpf_testmod" };

char _license[] SEC("license") = "GPL";
