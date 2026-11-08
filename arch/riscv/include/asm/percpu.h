/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef __ASM_PERCPU_H
#define __ASM_PERCPU_H

#include <linux/bits.h>
#include <linux/preempt.h>

#include <asm/alternative-macros.h>
#include <asm/cmpxchg.h>
#include <asm/cpufeature-macros.h>
#include <asm/current.h>
#include <asm/hwcap.h>
#include <asm/irqflags.h>

#include <linux/thread_info.h>

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

/*
 * Use a real destination register instead of x0 even when the result is
 * unused. Implementations may execute rd=x0 AMOs at a memory controller
 * without returning the old value to the CPU. Value-returning AMOs are
 * more likely to execute near the CPU, for example in the L1 cache. This
 * better suits per-CPU data, which is typically accessed repeatedly by
 * the same CPU.
 *
 * https://lore.kernel.org/r/e7d539ed-ced0-4b96-8ecd-048a5b803b85@paulmck-laptop
 */
#define __PERCPU_AMO_OP_CASE(sfx, name, sz, amo_insn)			\
static inline void							\
__percpu_##name##_amo_case_##sz(void *ptr, unsigned long val)		\
{									\
	u##sz tmp;							\
									\
	asm volatile (							\
		"amo" #amo_insn #sfx " %[tmp], %[val], %[ptr]"	\
		: [ptr] "+A" (*(u##sz *)ptr), [tmp] "=r" (tmp)	\
		: [val] "r" ((u##sz)(val)));				\
}

__PERCPU_AMO_OP_CASE(.w, add, 32, add)
__PERCPU_AMO_OP_CASE(.w, and, 32, and)
__PERCPU_AMO_OP_CASE(.w, or, 32, or)

#ifdef CONFIG_64BIT
__PERCPU_AMO_OP_CASE(.d, add, 64, add)
__PERCPU_AMO_OP_CASE(.d, and, 64, and)
__PERCPU_AMO_OP_CASE(.d, or, 64, or)
#endif

static inline u32 __percpu_add_return_amo_case_32(void *ptr, unsigned long val)
{
	register u32 ret;

	asm volatile ("amoadd.w %[ret], %[val], %[ptr]"
		: [ptr] "+A" (*(u32 *)ptr), [ret] "=r" (ret)
		: [val] "r" ((u32)(val)));

	return ret + val;
}

#ifdef CONFIG_64BIT
static inline u64 __percpu_add_return_amo_case_64(void *ptr, unsigned long val)
{
	register u64 ret;

	asm volatile ("amoadd.d %[ret], %[val], %[ptr]"
		: [ptr] "+A" (*(u64 *)ptr), [ret] "=r" (ret)
		: [val] "r" ((u64)(val)));

	return ret + val;
}
#endif

#define PERCPU_8_16_GET_SHIFT(ptr)	(((unsigned long)(ptr) & 0x3) * BITS_PER_BYTE)
#define PERCPU_8_16_GET_MASK(sz)	GENMASK((sz) - 1, 0)
#define PERCPU_8_16_GET_PTR32(ptr)	((u32 *)((unsigned long)(ptr) & ~0x3))

static inline void __percpu_add_amo_case_8(void *ptr, unsigned long val)
{
	u8 tmp;

	if (IS_ENABLED(CONFIG_RISCV_ISA_ZABHA) &&
	    riscv_has_extension_unlikely(RISCV_ISA_EXT_ZABHA)) {
		asm volatile (".option push\n"
			".option arch, +zabha\n"
			"amoadd.b %[tmp], %[val], %[ptr]\n"
			".option pop"
			: [ptr] "+A" (*(u8 *)ptr), [tmp] "=r" (tmp)
			: [val] "r" ((u8)(val & PERCPU_8_16_GET_MASK(8))));
	} else {
		u32 *ptr32 = PERCPU_8_16_GET_PTR32(ptr);
		const unsigned long shift = PERCPU_8_16_GET_SHIFT(ptr);
		const u32 mask = PERCPU_8_16_GET_MASK(8) << shift;
		const u8 val_trunc = val & PERCPU_8_16_GET_MASK(8);
		u32 old, new;
		u8 field;

		asm volatile ("0: lr.w %0, %2\n"
			"and %3, %0, %4\n"
			"srl %3, %3, %5\n"
			"add %3, %3, %6\n"
			"and %3, %3, %8\n"
			"sll %3, %3, %5\n"
			"and %1, %0, %7\n"
			"or %1, %1, %3\n"
			"sc.w %1, %1, %2\n"
			"bnez %1, 0b\n"
			: "=&r"(old), "=&r"(new), "+A"(*ptr32), "=&r"(field)
			: "r"(mask), "r"(shift), "r"(val_trunc), "r"(~mask),
			  "r"(PERCPU_8_16_GET_MASK(8)));
	}
}

static inline void __percpu_add_amo_case_16(void *ptr, unsigned long val)
{
	u16 tmp;

	if (IS_ENABLED(CONFIG_RISCV_ISA_ZABHA) &&
	    riscv_has_extension_unlikely(RISCV_ISA_EXT_ZABHA)) {
		asm volatile (".option push\n"
			".option arch, +zabha\n"
			"amoadd.h %[tmp], %[val], %[ptr]\n"
			".option pop"
			: [ptr] "+A" (*(u16 *)ptr), [tmp] "=r" (tmp)
			: [val] "r" ((u16)(val & PERCPU_8_16_GET_MASK(16))));
	} else {
		u32 *ptr32 = PERCPU_8_16_GET_PTR32(ptr);
		const unsigned long shift = PERCPU_8_16_GET_SHIFT(ptr);
		const u32 mask = PERCPU_8_16_GET_MASK(16) << shift;
		const u16 val_trunc = val & PERCPU_8_16_GET_MASK(16);
		u32 old, new;
		u16 field;

		asm volatile ("0: lr.w %0, %2\n"
			"and %3, %0, %4\n"
			"srl %3, %3, %5\n"
			"add %3, %3, %6\n"
			"and %3, %3, %8\n"
			"sll %3, %3, %5\n"
			"and %1, %0, %7\n"
			"or %1, %1, %3\n"
			"sc.w %1, %1, %2\n"
			"bnez %1, 0b\n"
			: "=&r"(old), "=&r"(new), "+A"(*ptr32), "=&r"(field)
			: "r"(mask), "r"(shift), "r"(val_trunc), "r"(~mask),
			  "r"(PERCPU_8_16_GET_MASK(16)));
	}
}

static inline void __percpu_and_amo_case_8(void *ptr, unsigned long val)
{
	u8 tmp;

	if (IS_ENABLED(CONFIG_RISCV_ISA_ZABHA) &&
	    riscv_has_extension_unlikely(RISCV_ISA_EXT_ZABHA)) {
		asm volatile (".option push\n"
			".option arch, +zabha\n"
			"amoand.b %[tmp], %[val], %[ptr]\n"
			".option pop"
			: [ptr] "+A" (*(u8 *)ptr), [tmp] "=r" (tmp)
			: [val] "r" ((u8)(val & PERCPU_8_16_GET_MASK(8))));
	} else {
		u32 *ptr32 = PERCPU_8_16_GET_PTR32(ptr);
		const unsigned long shift = PERCPU_8_16_GET_SHIFT(ptr);
		const u32 mask = PERCPU_8_16_GET_MASK(8) << shift;
		const u8 val_trunc = val & PERCPU_8_16_GET_MASK(8);
		u32 old, new;
		u8 field;

		asm volatile ("0: lr.w %0, %2\n"
			"and %3, %0, %4\n"
			"srl %3, %3, %5\n"
			"and %3, %3, %6\n"
			"and %3, %3, %8\n"
			"sll %3, %3, %5\n"
			"and %1, %0, %7\n"
			"or %1, %1, %3\n"
			"sc.w %1, %1, %2\n"
			"bnez %1, 0b\n"
			: "=&r"(old), "=&r"(new), "+A"(*ptr32), "=&r"(field)
			: "r"(mask), "r"(shift), "r"(val_trunc), "r"(~mask),
			  "r"(PERCPU_8_16_GET_MASK(8)));
	}
}

static inline void __percpu_and_amo_case_16(void *ptr, unsigned long val)
{
	u16 tmp;

	if (IS_ENABLED(CONFIG_RISCV_ISA_ZABHA) &&
	    riscv_has_extension_unlikely(RISCV_ISA_EXT_ZABHA)) {
		asm volatile (".option push\n"
			".option arch, +zabha\n"
			"amoand.h %[tmp], %[val], %[ptr]\n"
			".option pop"
			: [ptr] "+A" (*(u16 *)ptr), [tmp] "=r" (tmp)
			: [val] "r" ((u16)(val & PERCPU_8_16_GET_MASK(16))));
	} else {
		u32 *ptr32 = PERCPU_8_16_GET_PTR32(ptr);
		const unsigned long shift = PERCPU_8_16_GET_SHIFT(ptr);
		const u32 mask = PERCPU_8_16_GET_MASK(16) << shift;
		const u16 val_trunc = val & PERCPU_8_16_GET_MASK(16);
		u32 old, new;
		u16 field;

		asm volatile ("0: lr.w %0, %2\n"
			"and %3, %0, %4\n"
			"srl %3, %3, %5\n"
			"and %3, %3, %6\n"
			"and %3, %3, %8\n"
			"sll %3, %3, %5\n"
			"and %1, %0, %7\n"
			"or %1, %1, %3\n"
			"sc.w %1, %1, %2\n"
			"bnez %1, 0b\n"
			: "=&r"(old), "=&r"(new), "+A"(*ptr32), "=&r"(field)
			: "r"(mask), "r"(shift), "r"(val_trunc), "r"(~mask),
			  "r"(PERCPU_8_16_GET_MASK(16)));
	}
}

static inline void __percpu_or_amo_case_8(void *ptr, unsigned long val)
{
	u8 tmp;

	if (IS_ENABLED(CONFIG_RISCV_ISA_ZABHA) &&
	    riscv_has_extension_unlikely(RISCV_ISA_EXT_ZABHA)) {
		asm volatile (".option push\n"
			".option arch, +zabha\n"
			"amoor.b %[tmp], %[val], %[ptr]\n"
			".option pop"
			: [ptr] "+A" (*(u8 *)ptr), [tmp] "=r" (tmp)
			: [val] "r" ((u8)(val & PERCPU_8_16_GET_MASK(8))));
	} else {
		u32 *ptr32 = PERCPU_8_16_GET_PTR32(ptr);
		const unsigned long shift = PERCPU_8_16_GET_SHIFT(ptr);
		const u32 mask = PERCPU_8_16_GET_MASK(8) << shift;
		const u8 val_trunc = val & PERCPU_8_16_GET_MASK(8);
		u32 old, new;
		u8 field;

		asm volatile ("0: lr.w %0, %2\n"
			"and %3, %0, %4\n"
			"srl %3, %3, %5\n"
			"or %3, %3, %6\n"
			"and %3, %3, %8\n"
			"sll %3, %3, %5\n"
			"and %1, %0, %7\n"
			"or %1, %1, %3\n"
			"sc.w %1, %1, %2\n"
			"bnez %1, 0b\n"
			: "=&r"(old), "=&r"(new), "+A"(*ptr32), "=&r"(field)
			: "r"(mask), "r"(shift), "r"(val_trunc), "r"(~mask),
			  "r"(PERCPU_8_16_GET_MASK(8)));
	}
}

static inline void __percpu_or_amo_case_16(void *ptr, unsigned long val)
{
	u16 tmp;

	if (IS_ENABLED(CONFIG_RISCV_ISA_ZABHA) &&
	    riscv_has_extension_unlikely(RISCV_ISA_EXT_ZABHA)) {
		asm volatile (".option push\n"
			".option arch, +zabha\n"
			"amoor.h %[tmp], %[val], %[ptr]\n"
			".option pop"
			: [ptr] "+A" (*(u16 *)ptr), [tmp] "=r" (tmp)
			: [val] "r" ((u16)(val & PERCPU_8_16_GET_MASK(16))));
	} else {
		u32 *ptr32 = PERCPU_8_16_GET_PTR32(ptr);
		const unsigned long shift = PERCPU_8_16_GET_SHIFT(ptr);
		const u32 mask = PERCPU_8_16_GET_MASK(16) << shift;
		const u16 val_trunc = val & PERCPU_8_16_GET_MASK(16);
		u32 old, new;
		u16 field;

		asm volatile ("0: lr.w %0, %2\n"
			"and %3, %0, %4\n"
			"srl %3, %3, %5\n"
			"or %3, %3, %6\n"
			"and %3, %3, %8\n"
			"sll %3, %3, %5\n"
			"and %1, %0, %7\n"
			"or %1, %1, %3\n"
			"sc.w %1, %1, %2\n"
			"bnez %1, 0b\n"
			: "=&r"(old), "=&r"(new), "+A"(*ptr32), "=&r"(field)
			: "r"(mask), "r"(shift), "r"(val_trunc), "r"(~mask),
			  "r"(PERCPU_8_16_GET_MASK(16)));
	}
}

static inline u8 __percpu_add_return_amo_case_8(void *ptr, unsigned long val)
{
	if (IS_ENABLED(CONFIG_RISCV_ISA_ZABHA) &&
	    riscv_has_extension_unlikely(RISCV_ISA_EXT_ZABHA)) {
		register u8 ret;

		asm volatile (".option push\n"
			".option arch, +zabha\n"
			"amoadd.b %[ret], %[val], %[ptr]\n"
			".option pop"
			: [ptr] "+A"(*(u8 *)ptr), [ret] "=r"(ret)
			: [val] "r"((u8)(val & PERCPU_8_16_GET_MASK(8))));
		return ret + (u8)(val & PERCPU_8_16_GET_MASK(8));
	}

	{
		u32 *ptr32 = PERCPU_8_16_GET_PTR32(ptr);
		const unsigned long shift = PERCPU_8_16_GET_SHIFT(ptr);
		const u32 mask = PERCPU_8_16_GET_MASK(8) << shift;
		const u32 inv_mask = ~mask;
		const u8 val_trunc = val & PERCPU_8_16_GET_MASK(8);
		u32 old, new, field;

		asm volatile ("0: lr.w %0, %3\n"
			"and %1, %0, %4\n"
			"srl %1, %1, %5\n"
			"add %1, %1, %6\n"
			"and %1, %1, %7\n"
			"sll %1, %1, %5\n"
			"and %2, %0, %8\n"
			"or %2, %2, %1\n"
			"sc.w %2, %2, %3\n"
			"bnez %2, 0b\n"
			: "=&r"(old), "=&r"(field), "=&r"(new), "+A"(*ptr32)
			: "r"(mask), "r"(shift), "r"(val_trunc),
			  "r"(PERCPU_8_16_GET_MASK(8)), "r"(inv_mask));
		return field >> shift;
	}
}

static inline u16 __percpu_add_return_amo_case_16(void *ptr, unsigned long val)
{
	if (IS_ENABLED(CONFIG_RISCV_ISA_ZABHA) &&
	    riscv_has_extension_unlikely(RISCV_ISA_EXT_ZABHA)) {
		register u16 ret;

		asm volatile (".option push\n"
			".option arch, +zabha\n"
			"amoadd.h %[ret], %[val], %[ptr]\n"
			".option pop"
			: [ptr] "+A"(*(u16 *)ptr), [ret] "=r"(ret)
			: [val] "r"((u16)(val & PERCPU_8_16_GET_MASK(16))));
		return ret + (u16)(val & PERCPU_8_16_GET_MASK(16));
	}

	{
		u32 *ptr32 = PERCPU_8_16_GET_PTR32(ptr);
		const unsigned long shift = PERCPU_8_16_GET_SHIFT(ptr);
		const u32 mask = PERCPU_8_16_GET_MASK(16) << shift;
		const u32 inv_mask = ~mask;
		const u16 val_trunc = val & PERCPU_8_16_GET_MASK(16);
		u32 old, new, field;

		asm volatile ("0: lr.w %0, %3\n"
			"and %1, %0, %4\n"
			"srl %1, %1, %5\n"
			"add %1, %1, %6\n"
			"and %1, %1, %7\n"
			"sll %1, %1, %5\n"
			"and %2, %0, %8\n"
			"or %2, %2, %1\n"
			"sc.w %2, %2, %3\n"
			"bnez %2, 0b\n"
			: "=&r"(old), "=&r"(field), "=&r"(new), "+A"(*ptr32)
			: "r"(mask), "r"(shift), "r"(val_trunc),
			  "r"(PERCPU_8_16_GET_MASK(16)), "r"(inv_mask));
		return field >> shift;
	}
}

/*
 * Put arch_cmpxchg_relaxed() behind a function boundary to isolate its macro
 * locals from those at the call site. asm-generic implements
 * this_cpu_try_cmpxchg_N() using this_cpu_cmpxchg_N() and a local named __old.
 * RISC-V's _arch_cmpxchg() also declares __old, so expanding it in the caller's
 * scope would turn its initializer into "__old = (__old)" and read the
 * uninitialized inner variable.
 *
 * __always_inline avoids an out-of-line call.
 * _pcp_protect_cmpxchg_return() provides the instrument_atomic_read_write()
 * hook that cmpxchg_relaxed() would otherwise provide.
 */
#define PERCPU_CMPXCHG_OP(sz)						\
static __always_inline unsigned long					\
__percpu_cmpxchg_case_##sz(void *ptr, unsigned long old,		\
			   unsigned long new)				\
{									\
	return arch_cmpxchg_relaxed((u##sz *)ptr, (u##sz)old,		\
				    (u##sz)new);			\
}

PERCPU_CMPXCHG_OP(8)
PERCPU_CMPXCHG_OP(16)
PERCPU_CMPXCHG_OP(32)

#ifdef CONFIG_64BIT
PERCPU_CMPXCHG_OP(64)
#endif

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

#define _pcp_protect_cmpxchg_return(op, pcp, old, new)			\
({									\
	typeof(pcp) __retval;						\
	typeof(pcp) *__pcp_ptr;						\
									\
	preempt_disable_notrace();					\
	__pcp_ptr = raw_cpu_ptr(&(pcp));				\
	instrument_atomic_read_write(__pcp_ptr, sizeof(*__pcp_ptr));	\
	__retval = (typeof(pcp))op(__pcp_ptr, (unsigned long)(old),	\
				     (unsigned long)(new));		\
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

#define this_cpu_and_1(pcp, val)	_pcp_protect(__percpu_and_amo_case_8, pcp, val)
#define this_cpu_and_2(pcp, val)	_pcp_protect(__percpu_and_amo_case_16, pcp, val)
#define this_cpu_and_4(pcp, val)	_pcp_protect(__percpu_and_amo_case_32, pcp, val)

#ifdef CONFIG_64BIT
#define this_cpu_and_8(pcp, val)	_pcp_protect(__percpu_and_amo_case_64, pcp, val)
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

#define this_cpu_cmpxchg_1(pcp, o, n)					\
	_pcp_protect_cmpxchg_return(__percpu_cmpxchg_case_8, pcp, o, n)

#define this_cpu_cmpxchg_2(pcp, o, n)					\
	_pcp_protect_cmpxchg_return(__percpu_cmpxchg_case_16, pcp, o, n)

#define this_cpu_cmpxchg_4(pcp, o, n)					\
	_pcp_protect_cmpxchg_return(__percpu_cmpxchg_case_32, pcp, o, n)

#ifdef CONFIG_64BIT
#define this_cpu_cmpxchg_8(pcp, o, n)					\
	_pcp_protect_cmpxchg_return(__percpu_cmpxchg_case_64, pcp, o, n)

#define this_cpu_cmpxchg64(pcp, o, n)	this_cpu_cmpxchg_8(pcp, o, n)
#endif

#ifdef system_has_cmpxchg128
static inline u128 __percpu_generic_cmpxchg128(void *ptr, u128 old_val,
						      u128 new_val)
{
	unsigned long flags;
	u128 *p = ptr;
	u128 ret;

	flags = arch_local_irq_save();
	ret = *p;
	if (ret == old_val)
		*p = new_val;
	arch_local_irq_restore(flags);

	return ret;
}

#define this_cpu_cmpxchg128(pcp, o, n)					\
({									\
	u128 old__ = (o), new__ = (n), ret__;				\
	typeof(pcp) *ptr__;						\
									\
	preempt_disable_notrace();					\
	ptr__ = raw_cpu_ptr(&(pcp));					\
	if (system_has_cmpxchg128())					\
		ret__ = cmpxchg128_local(ptr__, old__, new__);		\
	else								\
		ret__ = __percpu_generic_cmpxchg128(ptr__, old__, new__); \
	preempt_enable_notrace();					\
	ret__;								\
})
#endif

#define __my_cpu_offset (((struct thread_info *)current)->pcpu_offset)

#undef PERCPU_RW_OPS
#undef __PERCPU_AMO_OP_CASE
#undef PERCPU_8_16_GET_SHIFT
#undef PERCPU_8_16_GET_MASK
#undef PERCPU_8_16_GET_PTR32
#undef PERCPU_CMPXCHG_OP

#include <asm-generic/percpu.h>

#endif /* __ASM_PERCPU_H */
