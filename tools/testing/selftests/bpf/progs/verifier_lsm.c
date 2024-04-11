// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

SEC("lsm/file_alloc_security")
__description("lsm bpf prog exit with valid return code. test 1")
__success
__naked int return_code_vaild_test1(void)
{
	asm volatile ("					\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("lsm/file_alloc_security")
__description("lsm bpf prog exit with valid return code. test 2")
__success
__naked int return_code_vaild_test2(void)
{
	asm volatile ("					\
	r0 = -4095;					\
	exit;						\
"	::: __clobber_all);
}

SEC("lsm/file_alloc_security")
__description("lsm bpf prog exit with valid return code. test 3")
__success
__naked int return_code_vaild_test3(void)
{
	asm volatile ("                                 \
	call %[bpf_get_prandom_u32];                    \
	r0 <<= 63;                                      \
	r0 s>>= 63;                                     \
	r0 &= -13;                                      \
	exit;                                           \
	"      :
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("lsm/vm_enough_memory")
__description("lsm bpf prog exit with valid return code. test 4")
__success
__naked int return_code_vaild_test4(void)
{
	asm volatile ("					\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("lsm/vm_enough_memory")
__description("lsm bpf prog exit with valid return code. test 5")
__success
__naked int return_code_vaild_test5(void)
{
	asm volatile ("					\
	r0 = -4096;					\
	exit;						\
"	::: __clobber_all);
}

SEC("lsm/vm_enough_memory")
__description("lsm bpf prog exit with valid return code. test 6")
__success
__naked int return_code_vaild_test6(void)
{
	asm volatile ("					\
	r0 = 4096;					\
	exit;						\
"	::: __clobber_all);
}

SEC("lsm/file_free_security")
__description("lsm bpf prog exit with valid return code. test 7")
__success
__naked void return_code_vaild_test7(void)
{
	asm volatile ("					\
	r0 = -4096;					\
	exit;						\
"	::: __clobber_all);
}

SEC("lsm/file_free_security")
__description("lsm bpf prog exit with valid return code. test 8")
__success
__naked void return_code_vaild_test8(void)
{
	asm volatile ("					\
	r0 = 4096;					\
	exit;						\
"	::: __clobber_all);
}

SEC("lsm/file_alloc_security")
__description("lsm bpf prog exit with invalid return code. test 1")
__failure __msg("R0 has smin=1 smax=1 should have been in [-4095, 0]")
__naked int return_code_invalid_test1(void)
{
	asm volatile ("					\
	r0 = 1;						\
	exit;						\
"	::: __clobber_all);
}

SEC("lsm/file_alloc_security")
__description("lsm bpf prog exit with invalid return code. test 2")
__failure __msg("R0 has smin=-4096 smax=-4096 should have been in [-4095, 0]")
__naked int return_code_invalid_test2(void)
{
	asm volatile ("					\
	r0 = -4096;					\
	exit;						\
"	::: __clobber_all);
}

SEC("lsm/getprocattr")
__description("lsm disabled hook: getprocattr")
__failure __msg("points to disabled bpf lsm hook")
__naked int disabled_hook_test1(void)
{
	asm volatile ("					\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("lsm/setprocattr")
__description("lsm disabled hook: setprocattr")
__failure __msg("points to disabled bpf lsm hook")
__naked int disabled_hook_test2(void)
{
	asm volatile ("					\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("lsm/ismaclabel")
__description("lsm disabled hook: ismaclabel")
__failure __msg("points to disabled bpf lsm hook")
__naked int disabled_hook_test3(void)
{
	asm volatile ("					\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

char _license[] SEC("license") = "GPL";
