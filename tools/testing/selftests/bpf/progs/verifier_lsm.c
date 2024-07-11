// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

SEC("lsm/file_alloc_security")
__description("lsm bpf prog with -4095~0 retval. test 1")
__success
__naked int errno_zero_retval_test1(void *ctx)
{
	asm volatile (
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
}

SEC("lsm/file_alloc_security")
__description("lsm bpf prog with -4095~0 retval. test 2")
__success
__naked int errno_zero_retval_test2(void *ctx)
{
	asm volatile (
	"r0 = -4095;"
	"exit;"
	::: __clobber_all);
}

SEC("lsm/file_alloc_security")
__description("lsm bpf prog with -4095~0 retval. test 3")
__success
__naked int errno_zero_retval_test3(void *ctx)
{
	asm volatile (
	"call %[bpf_get_prandom_u32];"
	"r0 <<= 63;"
	"r0 s>>= 63;"
	"r0 &= -13;"
	"exit;"
	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("lsm/file_mprotect")
__description("lsm bpf prog with -4095~0 retval. test 4")
__failure __msg("R0 has smin=-4096 smax=-4096 should have been in [-4095, 0]")
__naked int errno_zero_retval_test4(void *ctx)
{
	asm volatile (
	"r0 = -4096;"
	"exit;"
	::: __clobber_all);
}

SEC("lsm/file_mprotect")
__description("lsm bpf prog with -4095~0 retval. test 5")
__failure __msg("R0 has smin=4096 smax=4096 should have been in [-4095, 0]")
__naked int errno_zero_retval_test5(void *ctx)
{
	asm volatile (
	"r0 = 4096;"
	"exit;"
	::: __clobber_all);
}

SEC("lsm/vm_enough_memory")
__description("lsm bpf prog with -4095~0 retval. test 6")
__failure __msg("R0 has smin=1 smax=1 should have been in [-4095, 0]")
__naked int errno_zero_retval_test6(void *ctx)
{
	asm volatile (
	"r0 = 1;"
	"exit;"
	::: __clobber_all);
}

SEC("lsm/audit_rule_known")
__description("lsm bpf prog with bool retval. test 1")
__success
__naked int bool_retval_test1(void *ctx)
{
	asm volatile (
	"r0 = 1;"
	"exit;"
	::: __clobber_all);
}

SEC("lsm/audit_rule_known")
__description("lsm bpf prog with bool retval. test 2")
__success
__success
__naked int bool_retval_test2(void *ctx)
{
	asm volatile (
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
}

SEC("lsm/audit_rule_known")
__description("lsm bpf prog with bool retval. test 3")
__failure __msg("R0 has smin=-1 smax=-1 should have been in [0, 1]")
__naked int bool_retval_test3(void *ctx)
{
	asm volatile (
	"r0 = -1;"
	"exit;"
	::: __clobber_all);
}

SEC("lsm/audit_rule_known")
__description("lsm bpf prog with bool retval. test 4")
__failure __msg("R0 has smin=2 smax=2 should have been in [0, 1]")
__naked int bool_retval_test4(void *ctx)
{
	asm volatile (
	"r0 = 2;"
	"exit;"
	::: __clobber_all);
}

SEC("lsm/file_free_security")
__success
__description("lsm bpf prog with void retval. test 1")
__naked int void_retval_test1(void *ctx)
{
	asm volatile (
	"r0 = -4096;"
	"exit;"
	::: __clobber_all);
}

SEC("lsm/file_free_security")
__success
__description("lsm bpf prog with void retval. test 2")
__naked int void_retval_test2(void *ctx)
{
	asm volatile (
	"r0 = 4096;"
	"exit;"
	::: __clobber_all);
}

SEC("lsm/audit_rule_match")
__description("lsm bpf prog read write valid output parameter success")
__success
__naked int outparam_valid_test(void *ctx)
{
	asm volatile (
	"r1 = *(u64 *)(r1 + 0x20);"
	"r2 = *(u8 *)(r1 + 0x0);"
	"r2 &= 0x1;"
	"*(u8 *)(r1 + 0x0) = r2;"
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
}

SEC("lsm/audit_rule_match")
__description("lsm bpf prog read write output parameter, invalid read offset")
__failure __msg("invalid read offset: 1 (expected 0, type=_Bool)")
__naked int outparam_invalid_read_offset(void *ctx)
{
	asm volatile (
	"r1 = *(u64 *)(r1 + 0x20);"
	"r2 = *(u8 *)(r1 + 0x1);"
	"r2 &= 0x1;"
	"*(u8 *)(r1 + 0x0) = r2;"
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
}

SEC("lsm/audit_rule_match")
__description("lsm bpf prog read write invalid output parameter, invalid read size")
__failure __msg("invalid read size: 2 (expected 1, type=_Bool)")
__naked int outparam_invalid_read_size(void *ctx)
{
	asm volatile (
	"r1 = *(u64 *)(r1 + 0x20);"
	"r2 = *(u16 *)(r1 + 0x0);"
	"r2 &= 0x1;"
	"*(u8 *)(r1 + 0x0) = r2;"
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
}

SEC("lsm/audit_rule_match")
__description("lsm bpf prog read write invalid output parameter, invalid write offset")
__failure __msg("invalid write offset: 1 (expected 0, type=_Bool)")
__naked int outparam_invalid_write_offset(void *ctx)
{
	asm volatile (
	"r1 = *(u64 *)(r1 + 0x20);"
	"r2 = *(u8 *)(r1 + 0x0);"
	"r2 &= 0x1;"
	"*(u8 *)(r1 + 0x1) = r2;"
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
}

SEC("lsm/audit_rule_match")
__description("lsm bpf prog read write invalid output parameter, invalid write size")
__failure __msg("invalid write size: 2 (expected 1, type=_Bool)")
__naked int outparam_invalid_write_size(void *ctx)
{
	asm volatile (
	"r1 = *(u64 *)(r1 + 0x20);"
	"r2 = *(u8 *)(r1 + 0x0);"
	"r2 &= 0x1;"
	"*(u16 *)(r1 + 0x0) = r2;"
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
}

/* hook prototype:
 * int bpf_lsm_secctx_to_secid(const char *secdata, u32 seclen, u32 *secid)
 *
 * although the last param is a pointer to u32, it iss not the output param for
 * return value.
 */
SEC("lsm/secctx_to_secid")
__description("lsm bpf prog read write invalid output parameter, not output param hook")
__failure __msg("invalid mem access 'scalar'")
__naked int outparam_invalid_hook(void *ctx)
{
	asm volatile (
	"r1 = *(u64 *)(r1 + 0x10);"
	"r2 = *(u32 *)(r1 + 0x0);"
	"r2 &= 0x1;"
	"*(u32 *)(r1 + 0x0) = r2;"
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
}

SEC("lsm/getprocattr")
__description("lsm disabled hook: getprocattr")
__failure __msg("points to disabled hook")
__naked int disabled_hook_test1(void *ctx)
{
	asm volatile (
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
}

SEC("lsm/setprocattr")
__description("lsm disabled hook: setprocattr")
__failure __msg("points to disabled hook")
__naked int disabled_hook_test2(void *ctx)
{
	asm volatile (
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
}

SEC("lsm/ismaclabel")
__description("lsm disabled hook: ismaclabel")
__failure __msg("points to disabled hook")
__naked int disabled_hook_test3(void *ctx)
{
	asm volatile (
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
}

char _license[] SEC("license") = "GPL";
