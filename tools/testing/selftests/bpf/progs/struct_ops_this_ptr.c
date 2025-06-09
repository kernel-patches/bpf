// SPDX-License-Identifier: GPL-2.0-only

#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "../test_kmods/bpf_testmod.h"
#include "../test_kmods/bpf_testmod_kfunc.h"
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

SEC("struct_ops")
int BPF_PROG(test1)
{
	return bpf_kfunc_st_ops_test_this_ptr_impl(NULL);
}

SEC("syscall")
__success __retval(1234)
int syscall_this_ptr(void *ctx)
{
	return bpf_testmod_ops3_call_test_1();
}

SEC(".struct_ops.link")
struct bpf_testmod_ops3 testmod_this_ptr = {
	.test_1 = (void *)test1,
	.data = 1234,
};


