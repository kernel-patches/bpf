// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "../test_kmods/bpf_testmod.h"
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

__u64 got_arg9 = 0;

SEC("struct_ops/test_trampoline")
int BPF_PROG(test_trampoline, int arg1, int arg2, int arg3,
			      int arg4, int arg5, int arg6,
			      int arg7, int arg8, int arg9)
{
	got_arg9 = arg9;

	return 0;
}

SEC(".struct_ops.link")
struct bpf_testmod_ops testmod_trampoline = {
	.test_trampoline = (void *)test_trampoline,
};
