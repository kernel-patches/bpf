// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "../test_kmods/bpf_testmod_kfunc.h"

/* Keep the kfunc BTF records used by the inline assembly. */
void __kfunc_btf_root(void)
{
	asm volatile ("" :
		: "r"(&bpf_kfunc_test_uninit_scalar),
		  "r"(&bpf_kfunc_test_uninit_struct),
		  "r"(&bpf_kfunc_test_uninit_mem),
		  "r"(&bpf_kfunc_test_uninit_mem_const),
		  "r"(&bpf_kfunc_test_uninit_multi),
		  "r"(&bpf_kfunc_test_uninit_alias),
		  "r"(&bpf_kfunc_test_uninit_pair),
		  "r"(&bpf_kfunc_test_uninit_stack));
}

SEC("tc")
__success __retval(42)
__flag(BPF_F_TEST_STATE_FREQ)
__caps_unpriv(CAP_BPF | CAP_NET_ADMIN)
__prepare_priv
__success_unpriv
__naked void scalar_poisoned_at_checkpoint(void)
{
	asm volatile (
		"*(u64 *)(r10 - 8) = 0;"
		"goto +0;"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_kfunc_test_uninit_scalar];"
		"r0 = *(u32 *)(r10 - 8);"
		"exit;"
		: : __imm(bpf_kfunc_test_uninit_scalar) : __clobber_all);
}

SEC("tc")
__success __retval(42)
__caps_unpriv(CAP_BPF | CAP_NET_ADMIN)
__prepare_priv
__success_unpriv
__naked void scalar_uninitialized(void)
{
	asm volatile (
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_kfunc_test_uninit_scalar];"
		"r0 = *(u32 *)(r10 - 8);"
		"exit;"
		: : __imm(bpf_kfunc_test_uninit_scalar) : __clobber_all);
}

SEC("tc")
__success __retval(10)
__flag(BPF_F_TEST_STATE_FREQ)
__caps_unpriv(CAP_BPF | CAP_NET_ADMIN)
__prepare_priv
__success_unpriv
__naked void struct_poisoned_at_checkpoint(void)
{
	asm volatile (
		"*(u64 *)(r10 - 16) = 0;"
		"*(u64 *)(r10 - 8) = 0;"
		"goto +0;"
		"r1 = r10;"
		"r1 += -16;"
		"call %[bpf_kfunc_test_uninit_struct];"
		"r0 = *(u32 *)(r10 - 16);"
		"r1 = *(u32 *)(r10 - 12);"
		"r0 += r1;"
		"r1 = *(u32 *)(r10 - 8);"
		"r0 += r1;"
		"r1 = *(u32 *)(r10 - 4);"
		"r0 += r1;"
		"exit;"
		: : __imm(bpf_kfunc_test_uninit_struct) : __clobber_all);
}

SEC("tc")
__success __retval(10)
__caps_unpriv(CAP_BPF | CAP_NET_ADMIN)
__prepare_priv
__success_unpriv
__naked void struct_uninitialized(void)
{
	asm volatile (
		"r1 = r10;"
		"r1 += -16;"
		"call %[bpf_kfunc_test_uninit_struct];"
		"r0 = *(u32 *)(r10 - 16);"
		"r1 = *(u32 *)(r10 - 12);"
		"r0 += r1;"
		"r1 = *(u32 *)(r10 - 8);"
		"r0 += r1;"
		"r1 = *(u32 *)(r10 - 4);"
		"r0 += r1;"
		"exit;"
		: : __imm(bpf_kfunc_test_uninit_struct) : __clobber_all);
}

SEC("tc")
__success __retval(0x2a2a2a2a)
__flag(BPF_F_TEST_STATE_FREQ)
__caps_unpriv(CAP_BPF | CAP_NET_ADMIN)
__prepare_priv
__success_unpriv
__naked void sized_buffer_poisoned_at_checkpoint(void)
{
	asm volatile (
		"*(u64 *)(r10 - 8) = 0;"
		"goto +0;"
		"r1 = r10;"
		"r1 += -8;"
		"r2 = 8;"
		"call %[bpf_kfunc_test_uninit_mem];"
		"r0 = *(u32 *)(r10 - 8);"
		"r1 = *(u32 *)(r10 - 4);"
		"if r0 == r1 goto +1;"
		"r0 = 0;"
		"exit;"
		: : __imm(bpf_kfunc_test_uninit_mem) : __clobber_all);
}

SEC("tc")
__success __retval(0x2a2a2a2a)
__caps_unpriv(CAP_BPF | CAP_NET_ADMIN)
__prepare_priv
__success_unpriv
__naked void constant_size_buffer_uninitialized(void)
{
	asm volatile (
		"r1 = r10;"
		"r1 += -8;"
		"r2 = 8;"
		"call %[bpf_kfunc_test_uninit_mem_const];"
		"r0 = *(u32 *)(r10 - 8);"
		"r1 = *(u32 *)(r10 - 4);"
		"if r0 == r1 goto +1;"
		"r0 = 0;"
		"exit;"
		: : __imm(bpf_kfunc_test_uninit_mem_const) : __clobber_all);
}

SEC("tc")
__success __retval(42)
__flag(BPF_F_TEST_STATE_FREQ)
__caps_unpriv(CAP_BPF | CAP_NET_ADMIN)
__prepare_priv
__success_unpriv
__naked void multiple_outputs(void)
{
	asm volatile (
		"*(u64 *)(r10 - 16) = 0;"
		"*(u64 *)(r10 - 8) = 0;"
		"goto +0;"
		"r1 = r10;"
		"r1 += -16;"
		"r2 = r10;"
		"r2 += -8;"
		"r3 = 8;"
		"call %[bpf_kfunc_test_uninit_multi];"
		"r0 = *(u32 *)(r10 - 16);"
		"r1 = *(u32 *)(r10 - 8);"
		"if r1 != 0x2a2a2a2a goto 1f;"
		"r1 = *(u32 *)(r10 - 4);"
		"if r1 == 0x2a2a2a2a goto 2f;"
	"1:;"
		"r0 = 0;"
	"2:;"
		"exit;"
		: : __imm(bpf_kfunc_test_uninit_multi) : __clobber_all);
}

SEC("tc")
__success __retval(42)
__caps_unpriv(CAP_BPF | CAP_NET_ADMIN)
__prepare_priv
__success_unpriv
__naked void variable_size_preserves_other_output(void)
{
	asm volatile (
		"r3 = *(u32 *)(r1 + 0);"
		"r3 &= 7;"
		"*(u64 *)(r10 - 8) = 0;"
		"r1 = r10;"
		"r1 += -16;"
		"r2 = r10;"
		"r2 += -8;"
		"call %[bpf_kfunc_test_uninit_multi];"
		"r0 = *(u32 *)(r10 - 16);"
		"exit;"
		: : __imm(bpf_kfunc_test_uninit_multi) : __clobber_all);
}

SEC("tc")
__success __retval(42)
__caps_unpriv(CAP_BPF | CAP_NET_ADMIN)
__prepare_priv
__success_unpriv
__naked void variable_size_initialized_buffer(void)
{
	asm volatile (
		"r2 = *(u32 *)(r1 + 0);"
		"r2 &= 7;"
		"r2 += 1;"
		"*(u64 *)(r10 - 8) = 0;"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_kfunc_test_uninit_mem];"
		"r0 = *(u8 *)(r10 - 8);"
		"exit;"
		: : __imm(bpf_kfunc_test_uninit_mem) : __clobber_all);
}

SEC("tc")
__success __retval(42)
__caps_unpriv(CAP_BPF | CAP_NET_ADMIN)
__prepare_priv
__failure_unpriv __msg_unpriv("invalid read from stack")
__naked void variable_size_uninitialized_buffer(void)
{
	asm volatile (
		"r2 = *(u32 *)(r1 + 0);"
		"r2 &= 7;"
		"r2 += 1;"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_kfunc_test_uninit_mem];"
		"r0 = *(u8 *)(r10 - 8);"
		"exit;"
		: : __imm(bpf_kfunc_test_uninit_mem) : __clobber_all);
}

SEC("tc")
__success __retval(42)
__naked void variable_offset_initialized_buffer(void)
{
	asm volatile (
		"r2 = *(u32 *)(r1 + 0);"
		"r2 &= 4;"
		"*(u64 *)(r10 - 8) = 0;"
		"r6 = r10;"
		"r6 += -8;"
		"r6 += r2;"
		"r1 = r6;"
		"call %[bpf_kfunc_test_uninit_scalar];"
		"r0 = *(u32 *)(r6 + 0);"
		"exit;"
		: : __imm(bpf_kfunc_test_uninit_scalar) : __clobber_all);
}

SEC("tc")
__success
__caps_unpriv(CAP_BPF | CAP_NET_ADMIN)
__prepare_priv
__failure_unpriv __msg_unpriv("invalid read from stack")
__naked void output_does_not_initialize_adjacent_bytes(void)
{
	asm volatile (
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_kfunc_test_uninit_scalar];"
		"r0 = *(u32 *)(r10 - 4);"
		"exit;"
		: : __imm(bpf_kfunc_test_uninit_scalar) : __clobber_all);
}

SEC("tc")
__success __retval(7)
__caps_unpriv(CAP_BPF | CAP_NET_ADMIN)
__prepare_priv
__success_unpriv
__naked void initialized_input_alias(void)
{
	asm volatile (
		"*(u64 *)(r10 - 8) = 7;"
		"r1 = r10;"
		"r1 += -8;"
		"r2 = r1;"
		"call %[bpf_kfunc_test_uninit_alias];"
		"exit;"
		: : __imm(bpf_kfunc_test_uninit_alias) : __clobber_all);
}

SEC("tc")
__success
__caps_unpriv(CAP_BPF | CAP_NET_ADMIN)
__prepare_priv
__failure_unpriv __msg_unpriv("invalid read from stack")
__naked void uninitialized_input_alias(void)
{
	asm volatile (
		"r1 = r10;"
		"r1 += -8;"
		"r2 = r1;"
		"call %[bpf_kfunc_test_uninit_alias];"
		"exit;"
		: : __imm(bpf_kfunc_test_uninit_alias) : __clobber_all);
}

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_WRONLY_PROG);
	__type(key, __u32);
	__type(value, int);
} write_only_map SEC(".maps");

SEC("tc")
__success __retval(0)
__caps_unpriv(CAP_BPF | CAP_NET_ADMIN)
__prepare_priv
__success_unpriv
int write_only_map_output(void *ctx)
{
	__u32 key = 0;
	int *out = bpf_map_lookup_elem(&write_only_map, &key);

	if (out)
		bpf_kfunc_test_uninit_scalar(out);
	return 0;
}

static const int read_only_output;

SEC("tc")
__failure __msg("write into map forbidden")
int read_only_map_output(void *ctx)
{
	bpf_kfunc_test_uninit_scalar((int *)&read_only_output);
	return 0;
}

SEC("tc")
__failure __msg("stack R1 off=-2 size=4")
__naked void output_out_of_bounds(void)
{
	asm volatile (
		"r1 = r10;"
		"r1 += -2;"
		"call %[bpf_kfunc_test_uninit_scalar];"
		"r0 = 0;"
		"exit;"
		: : __imm(bpf_kfunc_test_uninit_scalar) : __clobber_all);
}

SEC("tc")
__arch_x86_64 __arch_arm64
__success __retval(42)
__caps_unpriv(CAP_BPF | CAP_NET_ADMIN)
__prepare_priv
__success_unpriv
__naked void output_after_by_value_argument(void)
{
	asm volatile (
		"r1 = 20;"
		"r2 = 22;"
		"r3 = r10;"
		"r3 += -8;"
		"call %[bpf_kfunc_test_uninit_pair];"
		"r0 = *(u32 *)(r10 - 8);"
		"exit;"
		: : __imm(bpf_kfunc_test_uninit_pair) : __clobber_all);
}

#if defined(__BPF_FEATURE_STACK_ARGUMENT)
SEC("tc")
__arch_x86_64 __arch_arm64 __arch_riscv64
__success __retval(15)
__flag(BPF_F_TEST_STATE_FREQ)
__caps_unpriv(CAP_BPF | CAP_NET_ADMIN)
__prepare_priv
__success_unpriv
__naked void output_passed_on_stack(void)
{
	asm volatile (
		"*(u64 *)(r10 - 8) = 0;"
		"goto +0;"
		"r1 = 1;"
		"r2 = 2;"
		"r3 = 3;"
		"r4 = 4;"
		"r5 = 5;"
		"r6 = r10;"
		"r6 += -8;"
		"*(u64 *)(r11 - 8) = r6;"
		"call %[bpf_kfunc_test_uninit_stack];"
		"r0 = *(u32 *)(r10 - 8);"
		"exit;"
		: : __imm(bpf_kfunc_test_uninit_stack) : __clobber_all);
}
#endif

char _license[] SEC("license") = "GPL";
