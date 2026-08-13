// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

SEC("fexit/bpf_testmod_loop_test")
int test_kmod_btfs_nonexist(void *ctx)
{
	return 0;
}

/*
 * This should fail to load, because .kmod_btfs does not contain
 * the needed module 'bpf_testmod'.
 */
DEFINE_KMOD_BTFS(_needed_kmods) = { "module_nonexist" };

char _license[] SEC("license") = "GPL";
