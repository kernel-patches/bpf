// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

SEC("socket")
__description("check w reg equal if r reg upper32 bits 0")
__success
__naked void subreg_equality_1(void)
{
	asm volatile ("					\
	call %[bpf_ktime_get_ns];			\
	*(u64 *)(r10 - 8) = r0;				\
	r2 = *(u32 *)(r10 - 8);				\
	/* At this point upper 4-bytes of r2 are 0,	\
	 * thus insn w3 = w2 should propagate reg id,	\
	 * and w2 < 9 comparison would also propagate	\
	 * the range for r3.				\
	 */						\
	w3 = w2;					\
	if w2 < 9 goto l0_%=;				\
	exit;						\
l0_%=:	if r3 < 9 goto l1_%=;				\
	/* r1 read is illegal at this point */		\
	r0 -= r1;					\
l1_%=:	exit;						\
"	:
	: __imm(bpf_ktime_get_ns)
	: __clobber_all);
}

SEC("socket")
__description("check w reg equal if r reg upper32 bits not 0")
__success
__naked void subreg_equality_2(void)
{
	asm volatile ("					\
	call %[bpf_ktime_get_ns];			\
	r2 = r0;					\
	/* Upper 4-bytes of r2 may not be 0, so r3 does	\
	 * not equal r2. It does share r2's low 32 bits	\
	 * though, so w2 < 9 still bounds r3: the	\
	 * zero-extending mov leaves nothing above them.\
	 */						\
	w3 = w2;					\
	if w2 < 9 goto l0_%=;				\
	exit;						\
l0_%=:	if r3 < 9 goto l1_%=;				\
	/* unreachable, so the r1 read is never made */	\
	r0 -= r1;					\
l1_%=:	exit;						\
"	:
	: __imm(bpf_ktime_get_ns)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
