// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Hengqi Chen */

#include "vmlinux.h"
#include "bpf_misc.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

SEC("seccomp")
__description("seccomp no helper call")
__failure __msg("unknown func bpf_get_prandom_u32")
__naked void seccomp_no_helper_call(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 = 0;						\
	exit;"						\
	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("seccomp")
__description("seccomp invalid ctx access, write")
__failure __msg("invalid bpf_context access")
__naked void seccomp_ctx_write(void)
{
	asm volatile ("					\
	r2 = r1;					\
	*(u64*)(r2 + 8) = r1;				\
	r0 = 0;						\
	exit;"						\
	:
	:
	: __clobber_all);
}

SEC("seccomp")
__description("seccomp invalid ctx access, out of range")
__failure __msg("invalid bpf_context access")
__naked void seccomp_ctx_read_out_of_range(void)
{
	asm volatile ("					\
	r2 = *(u64*)(r1 + %[__bpf_seccomp_ctx_size]);	\
	r0 = 0;						\
	exit;"						\
	:
	: __imm_const(__bpf_seccomp_ctx_size, sizeof(struct seccomp_data))
	: __clobber_all);
}

SEC("seccomp")
__description("seccomp invalid ctx access, size too short")
__failure __msg("invalid bpf_context access")
__naked void seccomp_ctx_read_too_short1(void)
{
	asm volatile ("					\
	r2 = *(u8*)(r1 + %[__bpf_seccomp_ctx_nr]);	\
	r0 = 0;						\
	exit;"						\
	:
	: __imm_const(__bpf_seccomp_ctx_nr, offsetof(struct seccomp_data, nr))
	: __clobber_all);
}

SEC("seccomp")
__description("seccomp invalid ctx access, size too short")
__failure __msg("invalid bpf_context access")
__naked void seccomp_ctx_read_too_short2(void)
{
	asm volatile ("					\
	r2 = *(u16*)(r1 + %[__bpf_seccomp_ctx_arch]);	\
	r0 = 0;						\
	exit;"						\
	:
	: __imm_const(__bpf_seccomp_ctx_arch, offsetof(struct seccomp_data, arch))
	: __clobber_all);
}

SEC("seccomp")
__description("seccomp invalid ctx access, size too short")
__failure __msg("invalid bpf_context access")
__naked void seccomp_ctx_read_too_short3(void)
{
	asm volatile ("					\
	r2 = *(u32*)(r1 + %[__bpf_seccomp_ctx_ip]);	\
	r0 = 0;						\
	exit;"						\
	:
	: __imm_const(__bpf_seccomp_ctx_ip, offsetof(struct seccomp_data, instruction_pointer))
	: __clobber_all);
}

SEC("seccomp")
__description("seccomp invalid ctx access, size too short")
__failure __msg("invalid bpf_context access")
__naked void seccomp_ctx_read_too_short4(void)
{
	asm volatile ("					\
	r2 = *(u32*)(r1 + %[__bpf_seccomp_ctx_arg1]);	\
	r0 = 0;						\
	exit;"						\
	:
	: __imm_const(__bpf_seccomp_ctx_arg1, offsetof(struct seccomp_data, args[1]))
	: __clobber_all);
}

SEC("seccomp")
__description("seccomp invalid ctx access, size too large")
__failure __msg("invalid bpf_context access")
__naked void seccomp_ctx_read_too_large(void)
{
	asm volatile ("					\
	r2 = *(u64*)(r1 + %[__bpf_seccomp_ctx_nr]);	\
	r0 = 0;						\
	exit;"						\
	:
	: __imm_const(__bpf_seccomp_ctx_nr, offsetof(struct seccomp_data, nr))
	: __clobber_all);
}

SEC("seccomp")
__description("seccomp ctx access, valid")
__success __retval(0x5ecc0779)
__naked void seccomp_ctx_read_ok(void)
{
	asm volatile ("					\
	r2 = *(u32*)(r1 + %[__bpf_seccomp_ctx_nr]);	\
	r2 = *(u32*)(r1 + %[__bpf_seccomp_ctx_arch]);	\
	r2 = *(u64*)(r1 + %[__bpf_seccomp_ctx_ip]);	\
	r2 = *(u64*)(r1 + %[__bpf_seccomp_ctx_arg0]);	\
	r2 = *(u64*)(r1 + %[__bpf_seccomp_ctx_arg1]);	\
	r2 = *(u64*)(r1 + %[__bpf_seccomp_ctx_arg2]);	\
	r2 = *(u64*)(r1 + %[__bpf_seccomp_ctx_arg3]);	\
	r2 = *(u64*)(r1 + %[__bpf_seccomp_ctx_arg4]);	\
	r2 = *(u64*)(r1 + %[__bpf_seccomp_ctx_arg5]);	\
	r0 = 0x5ecc0779;				\
	exit;"						\
	:
	: __imm_const(__bpf_seccomp_ctx_nr, offsetof(struct seccomp_data, nr)),
	  __imm_const(__bpf_seccomp_ctx_arch, offsetof(struct seccomp_data, arch)),
	  __imm_const(__bpf_seccomp_ctx_ip, offsetof(struct seccomp_data, instruction_pointer)),
	  __imm_const(__bpf_seccomp_ctx_arg0, offsetof(struct seccomp_data, args[0])),
	  __imm_const(__bpf_seccomp_ctx_arg1, offsetof(struct seccomp_data, args[1])),
	  __imm_const(__bpf_seccomp_ctx_arg2, offsetof(struct seccomp_data, args[2])),
	  __imm_const(__bpf_seccomp_ctx_arg3, offsetof(struct seccomp_data, args[3])),
	  __imm_const(__bpf_seccomp_ctx_arg4, offsetof(struct seccomp_data, args[4])),
	  __imm_const(__bpf_seccomp_ctx_arg5, offsetof(struct seccomp_data, args[5]))
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
