// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

SEC("socket")
__description("MOV32S, S8")
__success __success_unpriv __retval(0x23)
__naked void mov32s_s8(void)
{
	asm volatile ("					\
	w0 = 0xff23;					\
	w0 = (s8)w0;					\
	exit;						\
"	::: __clobber_all);
}

SEC("socket")
__description("MOV32S, S16")
__success __success_unpriv __retval(0xFFFFff23)
__naked void mov32s_s16(void)
{
	asm volatile ("					\
	w0 = 0xff23;					\
	w0 = (s16)w0;					\
	exit;						\
"	::: __clobber_all);
}

SEC("socket")
__description("MOV64S, S8")
__success __success_unpriv __retval(-2)
__naked void mov64s_s8(void)
{
	asm volatile ("					\
	r0 = 0x1fe;					\
	r0 = (s8)r0;					\
	exit;						\
"	::: __clobber_all);
}

SEC("socket")
__description("MOV64S, S16")
__success __success_unpriv __retval(0xf23)
__naked void mov64s_s16(void)
{
	asm volatile ("					\
	r0 = 0xf0f23;					\
	r0 = (s16)r0;					\
	exit;						\
"	::: __clobber_all);
}

SEC("socket")
__description("MOV64S, S32")
__success __success_unpriv __retval(-2)
__naked void mov64s_s32(void)
{
	asm volatile ("					\
	r0 = 0xfffffffe;				\
	r0 = (s32)r0;					\
	exit;						\
"	::: __clobber_all);
}

char _license[] SEC("license") = "GPL";
