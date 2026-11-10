// SPDX-License-Identifier: GPL-2.0
/*
 * fmod_ret programs on the targets which the LLVM IR scanner finds in
 * bpf_test_retval, see test_kmods/bpf_testmod_retval.c. They may return only
 * 0 or the values of the "bpf_fmodret_retval:" tag of their target.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

/* bpf_testmod_retval_constant() returns -EINVAL */
SEC("fmod_ret/bpf_testmod_retval_constant")
__success
int BPF_PROG(constant_einval, int ret)
{
	return -22;
}

SEC("fmod_ret/bpf_testmod_retval_constant")
__success
int BPF_PROG(constant_zero, int ret)
{
	return 0;
}

SEC("fmod_ret/bpf_testmod_retval_constant")
__failure __msg("R0 should be 0 or one of -22")
int BPF_PROG(constant_other, int ret)
{
	return -1;
}

SEC("fmod_ret/bpf_testmod_retval_constant")
__failure __msg("R0 should be 0 or one of -22")
__naked void constant_unknown(void)
{
	asm volatile (
	"call %[bpf_get_prandom_u32];"
	"exit;"
	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/* A privileged program may return a pointer, but not here */
SEC("fmod_ret/bpf_testmod_retval_constant")
__failure __msg("R0 is not a known value (ctx)")
__naked void constant_pointer(void)
{
	asm volatile (
	"r0 = r1;"
	"exit;"
	::: __clobber_all);
}

/* The function returns int, so only the low 32 bits count */
SEC("fmod_ret/bpf_testmod_retval_constant")
__success
__naked void constant_32bit(void)
{
	asm volatile (
	"w0 = -22;"
	"exit;"
	::: __clobber_all);
}

/* Not 0, so the function is not called, but the caller would see 0 */
SEC("fmod_ret/bpf_testmod_retval_constant")
__failure __msg("R0 should be 0 or one of -22")
__naked void constant_high_bits(void)
{
	asm volatile (
	"r0 = 1;"
	"r0 <<= 32;"
	"exit;"
	::: __clobber_all);
}

/* bpf_testmod_retval_join() returns -EINVAL or -ERANGE */
SEC("fmod_ret/bpf_testmod_retval_join")
__success
int BPF_PROG(join_einval, int *result, int value, int ret)
{
	return -22;
}

SEC("fmod_ret/bpf_testmod_retval_join")
__success
int BPF_PROG(join_erange, int *result, int value, int ret)
{
	return -34;
}

SEC("fmod_ret/bpf_testmod_retval_join")
__failure __msg("R0 should be 0 or one of -34,-22")
int BPF_PROG(join_other, int *result, int value, int ret)
{
	return -1;
}

/* Each path returns an allowed value */
SEC("fmod_ret/bpf_testmod_retval_join")
__success
__naked void join_both_paths(void)
{
	asm volatile (
	"r2 = *(u64 *)(r1 + 8);"
	"if r2 s< 0 goto 1f;"
	"r0 = -34;"
	"exit;"
"1:"
	"r0 = -22;"
	"exit;"
	::: __clobber_all);
}

/*
 * One of two paths to the same exit returns a forbidden value. The verifier
 * checks the allowed one first and must not prune the other.
 */
SEC("fmod_ret/bpf_testmod_retval_join")
__failure __msg("R0 should be 0 or one of -34,-22")
__naked void join_one_forbidden(void)
{
	asm volatile (
	"r2 = *(u64 *)(r1 + 8);"
	"if r2 s< 0 goto 1f;"
	"r0 = -34;"
	"goto 2f;"
"1:"
	"r0 = -1;"
"2:"
	"exit;"
	::: __clobber_all);
}

/* bpf_testmod_retval_first_errno() returns -1, a join with 0 is a range */
SEC("fmod_ret/bpf_testmod_retval_first_errno")
__success
__naked void first_errno_one_exit(void)
{
	asm volatile (
	"call %[bpf_get_prandom_u32];"
	"r1 = r0;"
	"r0 = 0;"
	"if r1 == 0 goto 1f;"
	"r0 = -1;"
"1:"
	"exit;"
	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/* R0 is -1 or 0, both are allowed */
SEC("fmod_ret/bpf_testmod_retval_first_errno")
__success
__naked void first_errno_range(void)
{
	asm volatile (
	"call %[bpf_get_prandom_u32];"
	"r0 &= 1;"
	"r0 -= 1;"
	"exit;"
	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/* R0 is 0 or 1, and 1 is not allowed */
SEC("fmod_ret/bpf_testmod_retval_first_errno")
__failure __msg("R0 should be 0 or one of -1")
__naked void first_errno_range_other(void)
{
	asm volatile (
	"call %[bpf_get_prandom_u32];"
	"r0 &= 1;"
	"exit;"
	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/* bpf_testmod_retval_wide() returns s64, so all 64 bits count */
SEC("fmod_ret/bpf_testmod_retval_wide")
__success
__load_if_JITed()
__naked void wide_64bit(void)
{
	asm volatile (
	"r0 = -14;"
	"exit;"
	::: __clobber_all);
}

SEC("fmod_ret/bpf_testmod_retval_wide")
__failure __msg("R0 should be 0 or one of -14")
__naked void wide_32bit(void)
{
	asm volatile (
	"w0 = -14;"
	"exit;"
	::: __clobber_all);
}

/* Declared targets are not restricted, in module and vmlinux BTF */
SEC("fmod_ret/bpf_testmod_retval_declared")
__success
int BPF_PROG(declared_module_any, int ret)
{
	return -1;
}

SEC("fmod_ret/bpf_modify_return_test")
__success
int BPF_PROG(declared_vmlinux_any, int a, int *b, int ret)
{
	return -1;
}

/* The error injection list allows any value although the target has a tag */
SEC("fmod_ret/bpf_testmod_retval_injectable")
__success
int BPF_PROG(static_rule_tagged, int value, int ret)
{
	return -1;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} jmp_table SEC(".maps");

/* A program in a program array may return any value */
SEC("fmod_ret/bpf_testmod_retval_constant")
__failure __msg("tail calls are not allowed in fmod_ret programs with restricted return values")
int BPF_PROG(constant_tail_call, int ret)
{
	bpf_tail_call(ctx, &jmp_table, 0);
	return 0;
}

SEC("fmod_ret/bpf_testmod_retval_declared")
__success
int BPF_PROG(declared_tail_call, int ret)
{
	bpf_tail_call(ctx, &jmp_table, 0);
	return 0;
}
