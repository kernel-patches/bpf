// SPDX-License-Identifier: GPL-2.0
/*
 * fmod_ret programs on functions of bpf_testmod which the build has tagged, see
 * test_kmods/bpf_testmod_retval.c. They may return only 0 or the errors in the
 * "bpf_fmodret_retval:" tag of their target.
 */
#include <vmlinux.h>
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

char _license[] SEC("license") = "GPL";

int pid;
bool deny;

/* What write() to /sys/kernel/bpf_testmod returns tells whether the function was called */
SEC("fmod_ret/bpf_testmod_retval_called")
__success
int BPF_PROG(called, size_t len, int ret)
{
	if (bpf_get_current_pid_tgid() >> 32 != pid)
		return 0;
	return deny ? -EINVAL : 0;
}

/* For the extensions of fmodret_retval_ext.c: "called" has a plain ctx */
SEC("fmod_ret/bpf_testmod_retval_called")
__success
int tagged_ctx(unsigned long long *ctx __arg_ctx)
{
	return 0;
}

SEC("fmod_ret/bpf_testmod_retval_called")
__failure __msg("At program exit the register R0 should be 0 or one of -27,-22")
int BPF_PROG(other_error, size_t len, int ret)
{
	return -EPERM;
}

/* Each path to the exit has an allowed value, their join has not */
SEC("fmod_ret/bpf_testmod_retval_called")
__success
__naked void two_paths(void)
{
	asm volatile (
	"r2 = *(u64 *)(r1 + 0);"
	"r0 = -27;"
	"if r2 == 7 goto 1f;"
	"r0 = -22;"
"1:"
	"exit;"
	::: __clobber_all);
}

/* Both ends of the range are in the list, the values between them are not */
SEC("fmod_ret/bpf_testmod_retval_called")
__failure __msg("R0 should be 0 or one of -27,-22")
__naked void range(void)
{
	asm volatile (
	"r0 = *(u64 *)(r1 + 0);"
	"if r0 s< -27 goto 1f;"
	"if r0 s> -22 goto 1f;"
	"exit;"
"1:"
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
}

/* The end of clang's "return a && b ? -EPERM : 0": [0, U32_MAX] in 64 bits, [-1, 0] in 32 */
SEC("fmod_ret/bpf_testmod_retval_eperm")
__success
__naked void negated_bool(void)
{
	asm volatile (
	"r0 = *(u64 *)(r1 + 0);"
	"w0 &= 1;"
	"w0 = -w0;"
	"exit;"
	::: __clobber_all);
}

/* Not 0, so the function is not called, but the caller would see 0 */
SEC("fmod_ret/bpf_testmod_retval_called")
__failure __msg("R0 should be 0 or one of -27,-22")
__naked void high_bits(void)
{
	asm volatile (
	"r0 = 1;"
	"r0 <<= 32;"
	"exit;"
	::: __clobber_all);
}

/* The function returns long, so all 64 bits count: this is 4294967282 */
SEC("fmod_ret/bpf_testmod_retval_long")
__failure __msg("R0 should be 0 or one of -28,-14")
__naked void zero_extended(void)
{
	asm volatile (
	"w0 = -14;"
	"exit;"
	::: __clobber_all);
}

/* A privileged program may return a pointer, but not here */
SEC("fmod_ret/bpf_testmod_retval_called")
__failure __msg("R0 is not a known value (ctx)")
__naked void pointer(void)
{
	asm volatile (
	"r0 = r1;"
	"exit;"
	::: __clobber_all);
}

/* The default exception callback returns the cookie */
SEC("fmod_ret/bpf_testmod_retval_denied")
__failure __msg("At program exit the register R1 should be 0 or one of -13")
int BPF_PROG(throws, int a, int b, int c, int d, int ret)
{
	if (a)
		bpf_throw(7);
	return 0;
}

/* An exception callback returns for the program */
__noinline int returns_eperm(u64 cookie)
{
	return -EPERM;
}

SEC("fmod_ret/bpf_testmod_retval_called")
__exception_cb(returns_eperm)
__failure __msg("R0 should be 0 or one of -27,-22")
int BPF_PROG(exception_cb, size_t len, int ret)
{
	if (len)
		bpf_throw(0);
	return 0;
}

/* As in two_paths, each path to the exit has an allowed value, their join has not */
__noinline int returns_two_errors(u64 cookie)
{
	register int err asm("r0");

	asm volatile (
	"r0 = -27;"
	"if %[cookie] == 7 goto 1f;"
	"r0 = -22;"
"1:"
	: "=r"(err) : [cookie] "r"(cookie));
	return err;
}

SEC("fmod_ret/bpf_testmod_retval_called")
__exception_cb(returns_two_errors)
__success
int BPF_PROG(exception_cb_two_paths, size_t len, int ret)
{
	if (len)
		bpf_throw(len);
	return 0;
}

SEC("fmod_ret/bpf_testmod_retval_minus_one")
__failure __msg("bpf_testmod_retval_minus_one() is not modifiable")
int BPF_PROG(not_a_target, int value, int ret)
{
	return 0;
}

/*
 * vmlinux has a bpf_dummy_reg() of the same type, so the two share the FUNC of
 * vmlinux. That one returns an error and has a tag. This one returns only 0.
 */
SEC("fmod_ret/bpf_testmod:bpf_dummy_reg")
__failure __msg("bpf_dummy_reg() is not modifiable")
int BPF_PROG(tag_of_vmlinux, void *kdata, struct bpf_link *link, int ret)
{
	return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} jmp_table SEC(".maps");

SEC("fmod_ret/bpf_testmod_retval_called")
__failure __msg("tail calls are not allowed in fmod_ret programs with restricted return values")
int BPF_PROG(tail_call, size_t len, int ret)
{
	bpf_tail_call(ctx, &jmp_table, 0);
	return 0;
}
