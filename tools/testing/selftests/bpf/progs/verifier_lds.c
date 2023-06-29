// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

SEC("socket")
__description("LDS, S8")
__success __success_unpriv __retval(-2)
__naked void lds_s8(void)
{
	asm volatile ("					\
	r1 = 0x3fe;					\
	*(u64 *)(r10 - 8) = r1;				\
	r0 = *(s8 *)(r10 - 8);				\
	exit;						\
"	::: __clobber_all);
}

SEC("socket")
__description("LDS, S16")
__success __success_unpriv __retval(-2)
__naked void lds_s16(void)
{
	asm volatile ("					\
	r1 = 0x3fffe;					\
	*(u64 *)(r10 - 8) = r1;				\
	r0 = *(s16 *)(r10 - 8);				\
	exit;						\
"	::: __clobber_all);
}

SEC("socket")
__description("LDS, S32")
__success __success_unpriv __retval(-2)
__naked void lds_s32(void)
{
	asm volatile ("					\
	r1 = 0xfffffffe;				\
	*(u64 *)(r10 - 8) = r1;				\
	r0 = *(s32 *)(r10 - 8);				\
	exit;						\
"	::: __clobber_all);
}

char _license[] SEC("license") = "GPL";
