// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Tejun Heo <tj@kernel.org> */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "../test_kmods/bpf_testmod_kfunc.h"

char _license[] SEC("license") = "GPL";

/* Keep the BTF FUNC record for the inline assembly references. */
void __kfunc_btf_root(void)
{
	bpf_kfunc_call_test_uninit(0);
}

SEC("tc")
__success __retval(42)
__naked void uninit_scalar_struct(void)
{
	asm volatile (
	"r1 = r10;"
	"r1 += -16;"
	"call %[bpf_kfunc_call_test_uninit];"
	"r1 = *(u32 *)(r10 - 16);"
	"if r1 != 1 goto 1f;"
	"r1 = *(u32 *)(r10 - 12);"
	"if r1 != 2 goto 1f;"
	"r1 = *(u32 *)(r10 - 8);"
	"if r1 != 3 goto 1f;"
	"r1 = *(u32 *)(r10 - 4);"
	"if r1 != 4 goto 1f;"
	"r0 = 42;"
	"exit;"
"1:"
	"r0 = 0;"
	"exit;"
	:: __imm(bpf_kfunc_call_test_uninit)
	: __clobber_all);
}

SEC("tc")
__success __retval(42)
__flag(BPF_F_TEST_STATE_FREQ)
__naked void uninit_scalar_struct_dead_store(void)
{
	asm volatile (
	"*(u64 *)(r10 - 16) = 0;"
	"*(u64 *)(r10 - 8) = 0;"
	"goto +0;"
	"r1 = r10;"
	"r1 += -16;"
	"call %[bpf_kfunc_call_test_uninit];"
	"r1 = *(u32 *)(r10 - 16);"
	"if r1 != 1 goto 1f;"
	"r1 = *(u32 *)(r10 - 12);"
	"if r1 != 2 goto 1f;"
	"r1 = *(u32 *)(r10 - 8);"
	"if r1 != 3 goto 1f;"
	"r1 = *(u32 *)(r10 - 4);"
	"if r1 != 4 goto 1f;"
	"r0 = 42;"
	"exit;"
"1:"
	"r0 = 0;"
	"exit;"
	:: __imm(bpf_kfunc_call_test_uninit)
	: __clobber_all);
}
