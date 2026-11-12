// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

#if (defined(__TARGET_ARCH_arm64) || defined(__TARGET_ARCH_x86) || \
	(defined(__TARGET_ARCH_riscv) && __riscv_xlen == 64) || \
	defined(__TARGET_ARCH_arm) || defined(__TARGET_ARCH_s390) || \
	defined(__TARGET_ARCH_loongarch)) && \
	(__clang_major__ >= 18 || defined(__BPF_FEATURE_MOVSX))

SEC("socket")
__description("MOV32SX, S8")
__success __success_unpriv __retval(0x23)
__naked void mov32sx_s8(void)
{
	asm volatile ("					\
	w0 = 0xff23;					\
	w0 = (s8)w0;					\
	exit;						\
"	::: __clobber_all);
}

SEC("socket")
__description("MOV32SX, S16")
__success __success_unpriv __retval(0xFFFFff23)
__naked void mov32sx_s16(void)
{
	asm volatile ("					\
	w0 = 0xff23;					\
	w0 = (s16)w0;					\
	exit;						\
"	::: __clobber_all);
}

SEC("socket")
__description("MOV64SX, S8")
__success __success_unpriv __retval(-2)
__naked void mov64sx_s8(void)
{
	asm volatile ("					\
	r0 = 0x1fe;					\
	r0 = (s8)r0;					\
	exit;						\
"	::: __clobber_all);
}

SEC("socket")
__description("MOV64SX, S16")
__success __success_unpriv __retval(0xf23)
__naked void mov64sx_s16(void)
{
	asm volatile ("					\
	r0 = 0xf0f23;					\
	r0 = (s16)r0;					\
	exit;						\
"	::: __clobber_all);
}

SEC("socket")
__description("MOV64SX, S32")
__success __success_unpriv __retval(-1)
__naked void mov64sx_s32(void)
{
	asm volatile ("					\
	r0 = 0xfffffffe;				\
	r0 = (s32)r0;					\
	r0 >>= 1;					\
	exit;						\
"	::: __clobber_all);
}

SEC("socket")
__description("MOV32SX, S8, range_check")
__success __success_unpriv __retval(1)
__naked void mov32sx_s8_range(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	w1 = (s8)w0;					\
	/* w1 with s8 range */				\
	if w1 s> 0x7f goto l0_%=;			\
	if w1 s< -0x80 goto l0_%=;			\
	r0 = 1;						\
l1_%=:							\
	exit;						\
l0_%=:							\
	r0 = 2;						\
	goto l1_%=;					\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__description("MOV32SX, S16, range_check")
__success __success_unpriv __retval(1)
__naked void mov32sx_s16_range(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	w1 = (s16)w0;					\
	/* w1 with s16 range */				\
	if w1 s> 0x7fff goto l0_%=;			\
	if w1 s< -0x80ff goto l0_%=;			\
	r0 = 1;						\
l1_%=:							\
	exit;						\
l0_%=:							\
	r0 = 2;						\
	goto l1_%=;					\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__description("MOV32SX, S16, range_check 2")
__success __success_unpriv __retval(1)
__naked void mov32sx_s16_range_2(void)
{
	asm volatile ("					\
	r1 = 65535;					\
	w2 = (s16)w1;					\
	r2 >>= 1;					\
	if r2 != 0x7fffFFFF goto l0_%=;			\
	r0 = 1;						\
l1_%=:							\
	exit;						\
l0_%=:							\
	r0 = 0;						\
	goto l1_%=;					\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__description("MOV64SX, S8, range_check")
__success __success_unpriv __retval(1)
__naked void mov64sx_s8_range(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r1 = (s8)r0;					\
	/* r1 with s8 range */				\
	if r1 s> 0x7f goto l0_%=;			\
	if r1 s< -0x80 goto l0_%=;			\
	r0 = 1;						\
l1_%=:							\
	exit;						\
l0_%=:							\
	r0 = 2;						\
	goto l1_%=;					\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__description("MOV64SX, S16, range_check")
__success __success_unpriv __retval(1)
__naked void mov64sx_s16_range(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r1 = (s16)r0;					\
	/* r1 with s16 range */				\
	if r1 s> 0x7fff goto l0_%=;			\
	if r1 s< -0x8000 goto l0_%=;			\
	r0 = 1;						\
l1_%=:							\
	exit;						\
l0_%=:							\
	r0 = 2;						\
	goto l1_%=;					\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__description("MOV64SX, S32, range_check")
__success __success_unpriv __retval(1)
__naked void mov64sx_s32_range(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r1 = (s32)r0;					\
	/* r1 with s32 range */				\
	if r1 s> 0x7fffffff goto l0_%=;			\
	if r1 s< -0x80000000 goto l0_%=;		\
	r0 = 1;						\
l1_%=:							\
	exit;						\
l0_%=:							\
	r0 = 2;						\
	goto l1_%=;					\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * A 32-bit range that already fits the signed N-bit range is unchanged by the sign
 * extension. Both of these straddle zero. The guard that follows can only be
 * resolved statically if the range survives, and it protects a div by zero.
 */
SEC("socket")
__description("MOV32SX, S8, negative range is preserved")
__success __success_unpriv __retval(0)
__naked void mov32sx_s8_negative_range(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	w0 &= 0x3f;					\
	w0 -= 0x3f;					\
	/* w0 is [-63, 0], already a valid s8 */	\
	w0 = (s8)w0;					\
	if w0 s< -0x3f goto l0_%=;			\
	w0 = 0;						\
	exit;						\
l0_%=:							\
	/* dead unless the range was widened */		\
	w0 /= 0;					\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__description("MOV32SX, S16, negative range is preserved")
__success __success_unpriv __retval(0)
__naked void mov32sx_s16_negative_range(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	w0 &= 0xfff;					\
	w0 -= 0xfff;					\
	/* w0 is [-4095, 0], already a valid s16 */	\
	w0 = (s16)w0;					\
	if w0 s< -0xfff goto l0_%=;			\
	w0 = 0;						\
	exit;						\
l0_%=:							\
	/* dead unless the range was widened */		\
	w0 /= 0;					\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * A 32-bit sign extension keeps the low 32 bits, so refining the source
 * reaches the destination. The source is a call return, which is the shape
 * bpf-gcc builds for "int err = helper(); if (err) ..".
 */
SEC("socket")
__success __retval(0)
__naked void sext_mov_unlinked_src(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r7 = (s32)r0;		/* r0 as the call defines it */	\
	if w0 != -1 goto l0_%=;	/* refines r0, propagates to r7 */ \
	if r7 == -1 goto l0_%=;	/* sign-extended, not 0xffffffff */ \
	r0 /= 0;						\
l0_%=:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * The propagation must not run backwards over the upper 32 bits: a sign extension
 * knows nothing about the upper bits of its source. r8's low 32 bits do become
 * 2, r8 == 2 does not follow.
 */
SEC("socket")
__failure __msg("div by zero")
__naked void sext_no_sync_from_subreg_base(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	r7 = (s32)r6;						\
	r8 = r6;						\
	r8 += 3;						\
	if r7 != -1 goto 1f;	/* pins the low 32 bits of r8 only */ \
	if r8 == 2 goto 1f;	/* taken only if r8 wrongly refined */	\
	r0 /= 0;						\
1:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * r2 is (u32)(r6 + 1) and r7 is (s32)(r6 + 1), so w2 == 1 means r7 == 1.
 * bpf-gcc builds "i += 1" for an int induction variable into exactly this shape.
 */
SEC("socket")
__success __retval(0)
__naked void sext_sync_from_zext_sibling(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	r6 <<= 32;						\
	call %[bpf_get_prandom_u32];				\
	r6 |= r0;		/* r6 = full 64-bit unknown */	\
	r2 = r6;						\
	w2 += 1;		/* r2 = (u32)(r6 + 1) */	\
	r7 = (s32)r2;		/* r7 = (s32)(r6 + 1) */	\
	if w2 != 1 goto 1f;	/* propagates to r7 */		\
	if r7 == 1 goto 1f;					\
	r0 /= 0;						\
1:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * "w6 = w6" leaves r6 in [0, U32_MAX]. A signed compare on its sign extension
 * must not hand r6 the sign-extended value: that drops every r6 >= 2^31 from
 * the range and makes the guarded div provably dead.
 */
SEC("socket")
__failure __msg("div by zero")
__naked void sext_narrow_base_keeps_high_values(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	w6 = w6;		/* r6 in [0, U32_MAX] */	\
	r7 = (s32)r6;						\
	r8 = 1;							\
	r8 <<= 31;		/* 0x80000000 */		\
	if r7 s> 100 goto 1f;	/* r6 is [0,100] or >= 2^31 */	\
	if r6 < r8 goto 1f;	/* reachable: r6 may be >= 2^31 */ \
	r0 /= 0;						\
1:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * A base/step line does not survive the sign extension: it subtracts 2^32,
 * and 2^32 is not a multiple of 3. r6 = 0x80000007 is a multiple of 3, so
 * r7 = -2147483641 is reachable.
 */
SEC("socket")
__failure __msg("div by zero")
__naked void sext_drops_stale_step(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	w6 = w6;						\
	r6 *= 3;		/* base 0, step 3 */		\
	r7 = (s32)r6;						\
	r8 = 1;							\
	r8 <<= 31;						\
	r9 = r8;						\
	r9 += 7;						\
	if r6 < r8 goto 1f;					\
	if r6 > r9 goto 1f;	/* r6 in [0x80000000, 0x80000007] */ \
	if r7 != -2147483641 goto 1f; /* reachable: r6 == 0x80000007 */ \
	r0 /= 0;						\
1:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__description("MOV64SX, S16, R10 Sign Extension")
__failure __msg("R1 type=scalar expected=fp, pkt, pkt_meta, map_key, map_value, mem, ringbuf_mem, buf, trusted_ptr_")
__failure_unpriv __msg_unpriv("R10 sign-extension part of pointer")
__naked void mov64sx_s16_r10(void)
{
	asm volatile ("					\
	r1 = 553656332;					\
	*(u32 *)(r10 - 8) = r1; 			\
	r1 = (s16)r10;					\
	r1 += -8;					\
	r2 = 3;						\
	if r2 <= r1 goto l0_%=;				\
l0_%=:							\
	call %[bpf_trace_printk];			\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_trace_printk)
	: __clobber_all);
}

SEC("socket")
__description("MOV32SX, S8, var_off u32_max")
__success __log_level(2)
__msg("w7 = (s8)w3 {{.*}}R7=scalar({{.*}}smin32=-128,smax32=127,var_off=(0x0; 0xffffffff))")
__failure_unpriv __msg_unpriv("back-edge from insn 2 to 0")
__naked void mov64sx_s32_varoff_1(void)
{
	asm volatile ("					\
l0_%=:							\
	r3 = *(u8 *)(r10 -387);				\
	w7 = (s8)w3;					\
	if w7 >= 0x2533823b goto l0_%=;			\
	w0 = 0;						\
	exit;						\
"	:
	:
	: __clobber_all);
}

SEC("socket")
__description("MOV32SX, S8, var_off not u32_max, positive after s8 extension")
__success __retval(0)
__success_unpriv
#ifdef SPEC_V1
__xlated_unpriv("w0 = 0")
__xlated_unpriv("exit")
__xlated_unpriv("nospec") /* inserted to prevent `frame pointer is read only` */
__xlated_unpriv("goto pc-1")
#endif
__naked void mov64sx_s32_varoff_2(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r3 = r0;					\
	r3 &= 0xf;					\
	w7 = (s8)w3;					\
	if w7 s>= 16 goto l0_%=;			\
	w0 = 0;						\
	exit;						\
l0_%=:							\
	r10 = 1;					\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__description("MOV32SX, S8, var_off not u32_max, negative after s8 extension")
__success __retval(0)
__success_unpriv
#ifdef SPEC_V1
__xlated_unpriv("w0 = 0")
__xlated_unpriv("exit")
__xlated_unpriv("nospec") /* inserted to prevent `frame pointer is read only` */
__xlated_unpriv("goto pc-1")
#endif
__naked void mov64sx_s32_varoff_3(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r3 = r0;					\
	r3 &= 0xf;					\
	r3 |= 0x80;					\
	w7 = (s8)w3;					\
	if w7 s>= -5 goto l0_%=;			\
	w0 = 0;						\
	exit;						\
l0_%=:							\
	r10 = 1;					\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__description("MOV64SX, S8, unsigned range_check")
__success __retval(0)
__naked void mov64sx_s8_range_check(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 &= 0x1;					\
	r0 += 0xfe;					\
	r0 = (s8)r0;					\
	if r0 < 0xfffffffffffffffe goto label_%=;	\
	r0 = 0;						\
	exit;						\
label_%=:						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__description("MOV32SX, S8, unsigned range_check")
__success __retval(0)
__naked void mov32sx_s8_range_check(void)
{
	asm volatile ("                                 \
	call %[bpf_get_prandom_u32];                    \
	w0 &= 0x1;                                      \
	w0 += 0xfe;                                     \
	w0 = (s8)w0;                                    \
	if w0 < 0xfffffffe goto label_%=;               \
	r0 = 0;                                         \
	exit;                                           \
label_%=: 	                                        \
	exit;                                           \
	"      :
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

#else

SEC("socket")
__description("cpuv4 is not supported by compiler or jit, use a dummy test")
__skip("cpuv4 is not supported by compiler or jit")
__success
int dummy_test(void)
{
	return 0;
}

#endif

char _license[] SEC("license") = "GPL";
