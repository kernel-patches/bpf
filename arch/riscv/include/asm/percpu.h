/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef __ASM_PERCPU_H
#define __ASM_PERCPU_H

#include <linux/bits.h>
#include <linux/preempt.h>

#include <asm/alternative-macros.h>
#include <asm/cpufeature-macros.h>
#include <asm/hwcap.h>

#define PERCPU_RW_OPS(sz)						\
static inline unsigned long __percpu_read_##sz(void *ptr)		\
{									\
	return READ_ONCE(*(u##sz *)ptr);				\
}									\
									\
static inline void __percpu_write_##sz(void *ptr, unsigned long val)	\
{									\
	WRITE_ONCE(*(u##sz *)ptr, (u##sz)val);				\
}

PERCPU_RW_OPS(8)
PERCPU_RW_OPS(16)
PERCPU_RW_OPS(32)

#ifdef CONFIG_64BIT
PERCPU_RW_OPS(64)
#endif

#define __PERCPU_AMO_OP_CASE(sfx, name, sz, amo_insn)			\
static inline void							\
__percpu_##name##_amo_case_##sz(void *ptr, unsigned long val)		\
{									\
	asm volatile (							\
		"amo" #amo_insn #sfx " zero, %[val], %[ptr]"		\
		: [ptr] "+A" (*(u##sz *)ptr)				\
		: [val] "r" ((u##sz)(val))				\
		: "memory");						\
}

#ifdef CONFIG_64BIT
#define PERCPU_OP(name, amo_insn)					\
	__PERCPU_AMO_OP_CASE(.w, name, 32, amo_insn)			\
	__PERCPU_AMO_OP_CASE(.d, name, 64, amo_insn)
#else
#define PERCPU_OP(name, amo_insn)					\
	__PERCPU_AMO_OP_CASE(.w, name, 32, amo_insn)
#endif

PERCPU_OP(add, add)
PERCPU_OP(andnot, and)
PERCPU_OP(or, or)

/*
 * Currently, only this_cpu_add_return_xxx() requires a return value,
 * and the PERCPU_RET_OP() does not account for other operations.
 */
#define __PERCPU_AMO_RET_OP_CASE(sfx, name, sz, amo_insn)		\
static inline u##sz							\
__percpu_##name##_return_amo_case_##sz(void *ptr, unsigned long val)	\
{									\
	register u##sz ret;						\
									\
	asm volatile (							\
		"amo" #amo_insn #sfx " %[ret], %[val], %[ptr]"		\
		: [ptr] "+A" (*(u##sz *)ptr), [ret] "=r" (ret)		\
		: [val] "r" ((u##sz)(val))				\
		: "memory");						\
									\
	return ret + val;						\
}

#ifdef CONFIG_64BIT
#define PERCPU_RET_OP(name, amo_insn)					\
	__PERCPU_AMO_RET_OP_CASE(.w, name, 32, amo_insn)		\
	__PERCPU_AMO_RET_OP_CASE(.d, name, 64, amo_insn)
#else
#define PERCPU_RET_OP(name, amo_insn)					\
	__PERCPU_AMO_RET_OP_CASE(.w, name, 32, amo_insn)
#endif

PERCPU_RET_OP(add, add)

#define PERCPU_8_16_GET_SHIFT(ptr)	(((unsigned long)(ptr) & 0x3) * BITS_PER_BYTE)
#define PERCPU_8_16_GET_MASK(sz)	GENMASK((sz) - 1, 0)
#define PERCPU_8_16_GET_PTR32(ptr)	((u32 *)((unsigned long)(ptr) & ~0x3))

#define PERCPU_8_16_OP(name, amo_insn, sz, sfx, val_type, new_val_expr, asm_op)			\
static inline void __percpu_##name##_amo_case_##sz(void *ptr, unsigned long val)		\
{												\
	if (IS_ENABLED(CONFIG_RISCV_ISA_ZABHA) &&						\
		riscv_has_extension_unlikely(RISCV_ISA_EXT_ZABHA)) {				\
		asm volatile ("amo" #amo_insn #sfx " zero, %[val], %[ptr]"			\
			: [ptr] "+A"(*(val_type *)ptr)						\
			: [val] "r"((val_type)((new_val_expr) & PERCPU_8_16_GET_MASK(sz)))	\
			: "memory");								\
	} else {										\
		u32 *ptr32 = PERCPU_8_16_GET_PTR32(ptr);					\
		const unsigned long shift = PERCPU_8_16_GET_SHIFT(ptr);				\
		const u32 mask = PERCPU_8_16_GET_MASK(sz) << shift;				\
		const val_type val_trunc = (val_type)((new_val_expr)				\
					   & PERCPU_8_16_GET_MASK(sz));				\
		u32 retx, rc;									\
		val_type new_val_type;								\
												\
		asm volatile (									\
			"0: lr.w %0, %2\n"							\
			"and %3, %0, %4\n"							\
			"srl %3, %3, %5\n"							\
			#asm_op " %3, %3, %6\n"							\
			"and %3, %3, %8\n"						\
			"sll %3, %3, %5\n"							\
			"and %1, %0, %7\n"							\
			"or %1, %1, %3\n"							\
			"sc.w %1, %1, %2\n"							\
			"bnez %1, 0b\n"								\
			: "=&r"(retx), "=&r"(rc), "+A"(*ptr32), "=&r"(new_val_type)		\
			: "r"(mask), "r"(shift), "r"(val_trunc), "r"(~mask),			\
			  "r"(PERCPU_8_16_GET_MASK(sz))						\
			: "memory");								\
		}										\
}

#define PERCPU_OP_8_16(op_name, op, expr, final_op)			\
	PERCPU_8_16_OP(op_name, op, 8, .b, u8, expr, final_op);		\
	PERCPU_8_16_OP(op_name, op, 16, .h, u16, expr, final_op)

PERCPU_OP_8_16(add, add, val, add)
PERCPU_OP_8_16(andnot, and, ~(val), and)
PERCPU_OP_8_16(or, or, val, or)

#define PERCPU_8_16_RET_OP(name, amo_insn, sz, sfx, val_type, new_val_expr)			\
static inline val_type __percpu_##name##_return_amo_case_##sz(void *ptr, unsigned long val)	\
{												\
	if (IS_ENABLED(CONFIG_RISCV_ISA_ZABHA) &&						\
		riscv_has_extension_unlikely(RISCV_ISA_EXT_ZABHA)) {				\
		register val_type ret;								\
		asm volatile ("amo" #amo_insn #sfx " %[ret], %[val], %[ptr]"			\
			: [ptr] "+A"(*(val_type *)ptr), [ret] "=r"(ret)				\
			: [val] "r"((val_type)((new_val_expr) & PERCPU_8_16_GET_MASK(sz)))	\
			: "memory");								\
		return ret + (val_type)((new_val_expr) & PERCPU_8_16_GET_MASK(sz));		\
	} else {										\
		u32 *ptr32 = PERCPU_8_16_GET_PTR32(ptr);					\
		const unsigned long shift = PERCPU_8_16_GET_SHIFT(ptr);				\
		const u32 mask = (PERCPU_8_16_GET_MASK(sz) << shift);				\
		const u32 inv_mask = ~mask;							\
		const val_type val_trunc = (val_type)((new_val_expr)				\
					   & PERCPU_8_16_GET_MASK(sz));				\
		u32 old, new, tmp;								\
												\
		asm volatile (									\
			"0: lr.w %0, %3\n"							\
			"and %1, %0, %4\n"							\
			"srl %1, %1, %5\n"							\
			"add %1, %1, %6\n"							\
			"and %1, %1, %7\n"							\
			"sll %1, %1, %5\n"							\
			"and %2, %0, %8\n"							\
			"or %2, %2, %1\n"							\
			"sc.w %2, %2, %3\n"							\
			"bnez %2, 0b\n"								\
			: "=&r"(old), "=&r"(tmp), "=&r"(new), "+A"(*ptr32)			\
			: "r"(mask), "r"(shift), "r"(val_trunc), "r"(PERCPU_8_16_GET_MASK(sz)), \
			"r"(inv_mask)								\
			: "memory");								\
		return (val_type)(tmp >> shift);						\
	}											\
}

PERCPU_8_16_RET_OP(add, add, 8, .b, u8, val)
PERCPU_8_16_RET_OP(add, add, 16, .h, u16, val)

#define _pcp_protect(op, pcp, ...)					\
({									\
	preempt_disable_notrace();					\
	op(raw_cpu_ptr(&(pcp)), __VA_ARGS__);				\
	preempt_enable_notrace();					\
})

#define _pcp_protect_return(op, pcp, args...)				\
({									\
	typeof(pcp) __retval;						\
	preempt_disable_notrace();					\
	__retval = (typeof(pcp))op(raw_cpu_ptr(&(pcp)), ##args);	\
	preempt_enable_notrace();					\
	__retval;							\
})

#define this_cpu_read_1(pcp)		_pcp_protect_return(__percpu_read_8, pcp)
#define this_cpu_read_2(pcp)		_pcp_protect_return(__percpu_read_16, pcp)
#define this_cpu_read_4(pcp)		_pcp_protect_return(__percpu_read_32, pcp)

#ifdef CONFIG_64BIT
#define this_cpu_read_8(pcp)		_pcp_protect_return(__percpu_read_64, pcp)
#endif

#define this_cpu_write_1(pcp, val)	_pcp_protect(__percpu_write_8, pcp, (unsigned long)val)
#define this_cpu_write_2(pcp, val)	_pcp_protect(__percpu_write_16, pcp, (unsigned long)val)
#define this_cpu_write_4(pcp, val)	_pcp_protect(__percpu_write_32, pcp, (unsigned long)val)

#ifdef CONFIG_64BIT
#define this_cpu_write_8(pcp, val)	_pcp_protect(__percpu_write_64, pcp, (unsigned long)val)
#endif

#define this_cpu_add_1(pcp, val)	_pcp_protect(__percpu_add_amo_case_8, pcp, val)
#define this_cpu_add_2(pcp, val)	_pcp_protect(__percpu_add_amo_case_16, pcp, val)
#define this_cpu_add_4(pcp, val)	_pcp_protect(__percpu_add_amo_case_32, pcp, val)

#ifdef CONFIG_64BIT
#define this_cpu_add_8(pcp, val)	_pcp_protect(__percpu_add_amo_case_64, pcp, val)
#endif

#define this_cpu_add_return_1(pcp, val)		\
_pcp_protect_return(__percpu_add_return_amo_case_8, pcp, val)

#define this_cpu_add_return_2(pcp, val)		\
_pcp_protect_return(__percpu_add_return_amo_case_16, pcp, val)

#define this_cpu_add_return_4(pcp, val)		\
_pcp_protect_return(__percpu_add_return_amo_case_32, pcp, val)

#ifdef CONFIG_64BIT
#define this_cpu_add_return_8(pcp, val)		\
_pcp_protect_return(__percpu_add_return_amo_case_64, pcp, val)
#endif

#define this_cpu_and_1(pcp, val)	_pcp_protect(__percpu_andnot_amo_case_8, pcp, ~(val))
#define this_cpu_and_2(pcp, val)	_pcp_protect(__percpu_andnot_amo_case_16, pcp, ~(val))
#define this_cpu_and_4(pcp, val)	_pcp_protect(__percpu_andnot_amo_case_32, pcp, val)

#ifdef CONFIG_64BIT
#define this_cpu_and_8(pcp, val)	_pcp_protect(__percpu_andnot_amo_case_64, pcp, val)
#endif

#define this_cpu_or_1(pcp, val)	_pcp_protect(__percpu_or_amo_case_8, pcp, val)
#define this_cpu_or_2(pcp, val)	_pcp_protect(__percpu_or_amo_case_16, pcp, val)
#define this_cpu_or_4(pcp, val)	_pcp_protect(__percpu_or_amo_case_32, pcp, val)

#ifdef CONFIG_64BIT
#define this_cpu_or_8(pcp, val)	_pcp_protect(__percpu_or_amo_case_64, pcp, val)
#endif

#define this_cpu_xchg_1(pcp, val)	_pcp_protect_return(xchg_relaxed, pcp, val)
#define this_cpu_xchg_2(pcp, val)	_pcp_protect_return(xchg_relaxed, pcp, val)
#define this_cpu_xchg_4(pcp, val)	_pcp_protect_return(xchg_relaxed, pcp, val)

#ifdef CONFIG_64BIT
#define this_cpu_xchg_8(pcp, val)	_pcp_protect_return(xchg_relaxed, pcp, val)
#endif

#define this_cpu_cmpxchg_1(pcp, o, n)	_pcp_protect_return(cmpxchg_relaxed, pcp, o, n)
#define this_cpu_cmpxchg_2(pcp, o, n)	_pcp_protect_return(cmpxchg_relaxed, pcp, o, n)
#define this_cpu_cmpxchg_4(pcp, o, n)	_pcp_protect_return(cmpxchg_relaxed, pcp, o, n)

#ifdef CONFIG_64BIT
#define this_cpu_cmpxchg_8(pcp, o, n)	_pcp_protect_return(cmpxchg_relaxed, pcp, o, n)

#define this_cpu_cmpxchg64(pcp, o, n)	this_cpu_cmpxchg_8(pcp, o, n)
#endif

#ifdef system_has_cmpxchg128
#define this_cpu_cmpxchg128(pcp, o, n)					\
({									\
	u128 ret__;							\
	typeof(pcp) *ptr__;						\
									\
	preempt_disable_notrace();					\
	ptr__ = raw_cpu_ptr(&(pcp));					\
	if (system_has_cmpxchg128())					\
		ret__ = cmpxchg128_local(ptr__, (o), (n));		\
	else								\
		ret__ = this_cpu_generic_cmpxchg(pcp, (o), (n));	\
	preempt_enable_notrace();					\
	ret__;								\
})
#endif

#include <asm-generic/percpu.h>

#endif /* __ASM_PERCPU_H */
