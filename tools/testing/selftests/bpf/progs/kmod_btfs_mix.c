// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

SEC("fexit/bpf_testmod_loop_test")
int test_kmod_btfs_mix(void *ctx)
{
	return 0;
}

/* mix of duplicated and unneeded modules */
DEFINE_KMOD_BTFS(_needed_kmods) = { "bpf_testmod", "bpf_testmod", "bpf_test_no_cfi" };

char _license[] SEC("license") = "GPL";
