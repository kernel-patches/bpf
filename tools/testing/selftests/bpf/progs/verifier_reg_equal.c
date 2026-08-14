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
__description("w reg shares r reg low32 via subreg link even if upper32 not 0")
__success
__naked void subreg_equality_2(void)
{
	asm volatile ("					\
	call %[bpf_ktime_get_ns];			\
	r2 = r0;					\
	/* Upper 4-bytes of r2 may not be 0. w3 = w2 is a 32-bit	\
	 * zero-extending mov, so w3 shares only r2 low 32 bits	\
	 * (a BPF_FLAG_SUBREG_ZEXT link) and its high bits are zero. The	\
	 * w2 < 9 comparison then narrows r3 to [0, 8] via the link,	\
	 * so if r3 < 9 is always taken and the illegal r1 read below	\
	 * is unreachable.				\
	 */						\
	w3 = w2;					\
	if w2 < 9 goto l0_%=;				\
	exit;						\
l0_%=:	if r3 < 9 goto l1_%=;				\
	/* unreachable: r3 is provably < 9 */		\
	r0 -= r1;					\
l1_%=:	exit;						\
"	:
	: __imm(bpf_ktime_get_ns)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
