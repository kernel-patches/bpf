/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ASM_PERCPU_H
#define __ASM_PERCPU_H

#include <linux/bits.h>
#include <linux/compiler.h>
#include <linux/stringify.h>
#include <linux/thread_info.h>

#include <asm/asm.h>
#include <asm/cpufeature-macros.h>
#include <asm/current.h>
#include <asm/gpr-num.h>
#include <asm/hwcap.h>

#define __my_cpu_offset (((struct thread_info *)current)->pcpu_offset)

#define PCPU_GPR_PCP_SHIFT	0
#define PCPU_GPR_PCP		GENMASK(4, 0)
#define PCPU_GPR_OFF_SHIFT	5
#define PCPU_GPR_OFF		GENMASK(9, 5)
#define PCPU_GPR_ADDR_SHIFT	10
#define PCPU_GPR_ADDR		GENMASK(14, 10)

#define __PCPU_GPR_NUM(gpr)	".L__gpr_num_" gpr

#define __PCPU_GPRS_VALUE						\
	"("								\
		"(" __PCPU_GPR_NUM("%[pcp]")  " << " __stringify(PCPU_GPR_PCP_SHIFT) ") | "	\
		"(" __PCPU_GPR_NUM("%[off]")  " << " __stringify(PCPU_GPR_OFF_SHIFT) ") | "	\
		"(" __PCPU_GPR_NUM("%[addr]") " << " __stringify(PCPU_GPR_ADDR_SHIFT) ")"	\
	")"

#define __PCPU_GPRS_ASSERT_DISTINCT					\
	".if ((" __PCPU_GPR_NUM("%[pcp]") " == " __PCPU_GPR_NUM("%[off]") ") || "	\
	      "(" __PCPU_GPR_NUM("%[pcp]") " == " __PCPU_GPR_NUM("%[addr]") ") || "	\
	      "(" __PCPU_GPR_NUM("%[off]") " == " __PCPU_GPR_NUM("%[addr]") "))\n"	\
	".error \"PCPU GPRs overlap\"\n"				\
	".endif\n"

/*
 * Mark a region where the per-CPU offset and address registers may need to
 * be rewritten by exception return after migration.  The three registers
 * must remain distinct for the whole region.
 */
#define __PCPU_GPRS_BEGIN						\
	__DEFINE_ASM_GPR_NUMS						\
	__PCPU_GPRS_ASSERT_DISTINCT					\
	"li %[off], " __PCPU_GPRS_VALUE "\n"				\
	"sh %[off], %[gprs]\n"						\
	REG_L " %[off], %[pcpu_offset]\n"				\
	"add %[addr], %[pcp], %[off]\n"

#define __PCPU_GPRS_END							\
	"sh zero, %[gprs]\n"

#define __PCPU_OP_CONTEXT()						\
	struct thread_info *__ti = (struct thread_info *)current;	\
	unsigned long __off, __addr

#define PERCPU_RW_OPS(load, store, sz)					\
static __always_inline unsigned long					\
__percpu_read_##sz(const void __percpu *pcp)				\
{									\
	__PCPU_OP_CONTEXT();						\
	unsigned long val;						\
									\
	asm volatile (__PCPU_GPRS_BEGIN					\
		load " %[val], 0(%[addr])\n"				\
		__PCPU_GPRS_END						\
		: [gprs] "=m" (__ti->pcpu_gprs),			\
		  [off] "=&r" (__off), [addr] "=&r" (__addr),		\
		  [val] "=&r" (val)					\
		: [pcpu_offset] "m" (__ti->pcpu_offset),		\
		  [pcp] "r" (pcp)					\
		: "memory");						\
									\
	return (u##sz)val;						\
}									\
									\
static __always_inline void __percpu_write_##sz(void __percpu *pcp,	\
				       unsigned long val)		\
{									\
	__PCPU_OP_CONTEXT();						\
									\
	asm volatile (__PCPU_GPRS_BEGIN					\
		store " %[val], 0(%[addr])\n"				\
		__PCPU_GPRS_END						\
		: [gprs] "=m" (__ti->pcpu_gprs),			\
		  [off] "=&r" (__off), [addr] "=&r" (__addr)		\
		: [pcpu_offset] "m" (__ti->pcpu_offset),		\
		  [pcp] "r" (pcp), [val] "r" ((u##sz)val)		\
		: "memory");						\
}

PERCPU_RW_OPS("lbu", "sb", 8)
PERCPU_RW_OPS("lhu", "sh", 16)

#ifdef CONFIG_64BIT
PERCPU_RW_OPS("lwu", "sw", 32)
PERCPU_RW_OPS("ld", "sd", 64)
#else
PERCPU_RW_OPS("lw", "sw", 32)
#endif

/*
 * Use value-returning AMOs even when the old value is unused.  Avoiding x0
 * as rd makes an AMO more likely to execute near the CPU, which better suits
 * CPU-local data that is commonly accessed again by the same CPU.
 */
#define __PERCPU_AMO_OP_CASE(sfx, name, sz, amo_insn)			\
static __always_inline void						\
__percpu_##name##_amo_case_##sz(void __percpu *pcp, unsigned long val)	\
{									\
	__PCPU_OP_CONTEXT();						\
	u##sz tmp;							\
									\
	asm volatile (__PCPU_GPRS_BEGIN					\
		"amo" #amo_insn #sfx " %[tmp], %[val], 0(%[addr])\n"	\
		__PCPU_GPRS_END						\
		: [gprs] "=m" (__ti->pcpu_gprs),			\
		  [off] "=&r" (__off), [addr] "=&r" (__addr),		\
		  [tmp] "=&r" (tmp)					\
		: [pcpu_offset] "m" (__ti->pcpu_offset),		\
		  [pcp] "r" (pcp), [val] "r" ((u##sz)val)		\
		: "memory");						\
}

__PERCPU_AMO_OP_CASE(.w, add, 32, add)
__PERCPU_AMO_OP_CASE(.w, and, 32, and)
__PERCPU_AMO_OP_CASE(.w, or, 32, or)

#ifdef CONFIG_64BIT
__PERCPU_AMO_OP_CASE(.d, add, 64, add)
__PERCPU_AMO_OP_CASE(.d, and, 64, and)
__PERCPU_AMO_OP_CASE(.d, or, 64, or)
#endif

#define PERCPU_8_16_GET_SHIFT(pcp)					\
	(((__force unsigned long)(pcp) & 0x3) * BITS_PER_BYTE)
#define PERCPU_8_16_GET_MASK(sz)	GENMASK((sz) - 1, 0)
#define PERCPU_8_16_GET_PCP32(pcp)					\
	((void __percpu *)((__force unsigned long)(pcp) & ~0x3UL))

#define __PERCPU_8_16_OP_CASE(name, sz, sfx, amo_insn, op_insn)		\
static __always_inline void						\
__percpu_##name##_amo_case_##sz(void __percpu *pcp, unsigned long val)	\
{									\
	__PCPU_OP_CONTEXT();						\
	const u32 field_mask = PERCPU_8_16_GET_MASK(sz);		\
	const unsigned long shift = PERCPU_8_16_GET_SHIFT(pcp);		\
	const u32 mask = field_mask << shift;				\
	const u32 val_trunc = val & field_mask;				\
	void __percpu *pcp32 = PERCPU_8_16_GET_PCP32(pcp);		\
	u32 old, new, field;						\
	u##sz tmp;							\
									\
	if (IS_ENABLED(CONFIG_RISCV_ISA_ZABHA) &&			\
	    riscv_has_extension_unlikely(RISCV_ISA_EXT_ZABHA)) {	\
		asm volatile (__PCPU_GPRS_BEGIN				\
			".option push\n"				\
			".option arch, +zabha\n"			\
			"amo" #amo_insn #sfx " %[tmp], %[val], 0(%[addr])\n"	\
			".option pop\n"					\
			__PCPU_GPRS_END					\
			: [gprs] "=m" (__ti->pcpu_gprs),		\
			  [off] "=&r" (__off), [addr] "=&r" (__addr),	\
			  [tmp] "=&r" (tmp)				\
			: [pcpu_offset] "m" (__ti->pcpu_offset),	\
			  [pcp] "r" (pcp), [val] "r" ((u##sz)val)	\
			: "memory");					\
	} else {							\
		asm volatile (__PCPU_GPRS_BEGIN				\
			"0: lr.w %[old], 0(%[addr])\n"			\
			"and %[field], %[old], %[mask]\n"		\
			"srl %[field], %[field], %[shift]\n"		\
			op_insn " %[field], %[field], %[val]\n"		\
			"and %[field], %[field], %[field_mask]\n"	\
			"sll %[field], %[field], %[shift]\n"		\
			"and %[new], %[old], %[inv_mask]\n"		\
			"or %[new], %[new], %[field]\n"			\
			"sc.w %[new], %[new], 0(%[addr])\n"		\
			"bnez %[new], 0b\n"				\
			__PCPU_GPRS_END					\
			: [gprs] "=m" (__ti->pcpu_gprs),		\
			  [off] "=&r" (__off), [addr] "=&r" (__addr),	\
			  [old] "=&r" (old), [new] "=&r" (new),		\
			  [field] "=&r" (field)				\
			: [pcpu_offset] "m" (__ti->pcpu_offset),	\
			  [pcp] "r" (pcp32), [mask] "r" (mask),		\
			  [shift] "r" (shift), [val] "r" (val_trunc),	\
			  [field_mask] "r" (field_mask),		\
			  [inv_mask] "r" (~mask)			\
			: "memory");					\
	}								\
}

__PERCPU_8_16_OP_CASE(add, 8, .b, add, "add")
__PERCPU_8_16_OP_CASE(add, 16, .h, add, "add")
__PERCPU_8_16_OP_CASE(and, 8, .b, and, "and")
__PERCPU_8_16_OP_CASE(and, 16, .h, and, "and")
__PERCPU_8_16_OP_CASE(or, 8, .b, or, "or")
__PERCPU_8_16_OP_CASE(or, 16, .h, or, "or")

static __always_inline u32
__percpu_add_return_amo_case_32(void __percpu *pcp, unsigned long val)
{
	__PCPU_OP_CONTEXT();
	u32 ret;

	asm volatile (__PCPU_GPRS_BEGIN
		"amoadd.w %[ret], %[val], 0(%[addr])\n"
		__PCPU_GPRS_END
		: [gprs] "=m" (__ti->pcpu_gprs),
		  [off] "=&r" (__off), [addr] "=&r" (__addr),
		  [ret] "=&r" (ret)
		: [pcpu_offset] "m" (__ti->pcpu_offset),
		  [pcp] "r" (pcp), [val] "r" ((u32)val)
		: "memory");

	return ret + (u32)val;
}

#ifdef CONFIG_64BIT
static __always_inline u64
__percpu_add_return_amo_case_64(void __percpu *pcp, unsigned long val)
{
	__PCPU_OP_CONTEXT();
	u64 ret;

	asm volatile (__PCPU_GPRS_BEGIN
		"amoadd.d %[ret], %[val], 0(%[addr])\n"
		__PCPU_GPRS_END
		: [gprs] "=m" (__ti->pcpu_gprs),
		  [off] "=&r" (__off), [addr] "=&r" (__addr),
		  [ret] "=&r" (ret)
		: [pcpu_offset] "m" (__ti->pcpu_offset),
		  [pcp] "r" (pcp), [val] "r" ((u64)val)
		: "memory");

	return ret + (u64)val;
}
#endif

static __always_inline unsigned long
__percpu_add_return_8_16(void __percpu *pcp, unsigned long val,
			 unsigned int bits)
{
	__PCPU_OP_CONTEXT();
	const u32 field_mask = GENMASK(bits - 1, 0);
	const unsigned long shift = PERCPU_8_16_GET_SHIFT(pcp);
	const u32 mask = field_mask << shift;
	const u32 val_trunc = val & field_mask;
	void __percpu *pcp32 = PERCPU_8_16_GET_PCP32(pcp);
	u32 old, new, field;
	unsigned long ret;

	if (IS_ENABLED(CONFIG_RISCV_ISA_ZABHA) &&
	    riscv_has_extension_unlikely(RISCV_ISA_EXT_ZABHA)) {
		if (bits == 8) {
			asm volatile (__PCPU_GPRS_BEGIN
				".option push\n"
				".option arch, +zabha\n"
				"amoadd.b %[ret], %[val], 0(%[addr])\n"
				".option pop\n"
				__PCPU_GPRS_END
				: [gprs] "=m" (__ti->pcpu_gprs),
				  [off] "=&r" (__off), [addr] "=&r" (__addr),
				  [ret] "=&r" (ret)
				: [pcpu_offset] "m" (__ti->pcpu_offset),
				  [pcp] "r" (pcp), [val] "r" ((u8)val)
				: "memory");
			return (u8)(ret + val);
		}

		asm volatile (__PCPU_GPRS_BEGIN
			".option push\n"
			".option arch, +zabha\n"
			"amoadd.h %[ret], %[val], 0(%[addr])\n"
			".option pop\n"
			__PCPU_GPRS_END
			: [gprs] "=m" (__ti->pcpu_gprs),
			  [off] "=&r" (__off), [addr] "=&r" (__addr),
			  [ret] "=&r" (ret)
			: [pcpu_offset] "m" (__ti->pcpu_offset),
			  [pcp] "r" (pcp), [val] "r" ((u16)val)
			: "memory");
		return (u16)(ret + val);
	}

	asm volatile (__PCPU_GPRS_BEGIN
		"0: lr.w %[old], 0(%[addr])\n"
		"and %[field], %[old], %[mask]\n"
		"srl %[field], %[field], %[shift]\n"
		"add %[field], %[field], %[val]\n"
		"and %[field], %[field], %[field_mask]\n"
		"sll %[field], %[field], %[shift]\n"
		"and %[new], %[old], %[inv_mask]\n"
		"or %[new], %[new], %[field]\n"
		"sc.w %[new], %[new], 0(%[addr])\n"
		"bnez %[new], 0b\n"
		__PCPU_GPRS_END
		: [gprs] "=m" (__ti->pcpu_gprs),
		  [off] "=&r" (__off), [addr] "=&r" (__addr),
		  [old] "=&r" (old), [new] "=&r" (new),
		  [field] "=&r" (field)
		: [pcpu_offset] "m" (__ti->pcpu_offset),
		  [pcp] "r" (pcp32), [mask] "r" (mask),
		  [shift] "r" (shift), [val] "r" (val_trunc),
		  [field_mask] "r" (field_mask), [inv_mask] "r" (~mask)
		: "memory");

	return field >> shift;
}

static __always_inline u8
__percpu_add_return_amo_case_8(void __percpu *pcp, unsigned long val)
{
	return __percpu_add_return_8_16(pcp, val, 8);
}

static __always_inline u16
__percpu_add_return_amo_case_16(void __percpu *pcp, unsigned long val)
{
	return __percpu_add_return_8_16(pcp, val, 16);
}

#define __PERCPU_XCHG_AMO_CASE(sfx, sz)					\
static __always_inline unsigned long					\
__percpu_xchg_case_##sz(void __percpu *pcp, unsigned long val)		\
{									\
	__PCPU_OP_CONTEXT();						\
	u##sz ret;							\
									\
	asm volatile (__PCPU_GPRS_BEGIN					\
		"amoswap" #sfx " %[ret], %[val], 0(%[addr])\n"		\
		__PCPU_GPRS_END						\
		: [gprs] "=m" (__ti->pcpu_gprs),			\
		  [off] "=&r" (__off), [addr] "=&r" (__addr),		\
		  [ret] "=&r" (ret)					\
		: [pcpu_offset] "m" (__ti->pcpu_offset),		\
		  [pcp] "r" (pcp), [val] "r" ((u##sz)val)		\
		: "memory");						\
									\
	return ret;							\
}

__PERCPU_XCHG_AMO_CASE(.w, 32)
#ifdef CONFIG_64BIT
__PERCPU_XCHG_AMO_CASE(.d, 64)
#endif

#define __PERCPU_8_16_XCHG_CASE(sz, sfx)				\
static __always_inline unsigned long					\
__percpu_xchg_case_##sz(void __percpu *pcp, unsigned long val)		\
{									\
	__PCPU_OP_CONTEXT();						\
	const u32 field_mask = PERCPU_8_16_GET_MASK(sz);		\
	const unsigned long shift = PERCPU_8_16_GET_SHIFT(pcp);		\
	const u32 mask = field_mask << shift;				\
	const u32 new_field = (val & field_mask) << shift;		\
	void __percpu *pcp32 = PERCPU_8_16_GET_PCP32(pcp);		\
	u32 old, new, rc;						\
	u##sz ret;							\
									\
	if (IS_ENABLED(CONFIG_RISCV_ISA_ZABHA) &&			\
	    riscv_has_extension_unlikely(RISCV_ISA_EXT_ZABHA)) {	\
		asm volatile (__PCPU_GPRS_BEGIN				\
			".option push\n"				\
			".option arch, +zabha\n"			\
			"amoswap" #sfx " %[ret], %[val], 0(%[addr])\n"	\
			".option pop\n"					\
			__PCPU_GPRS_END					\
			: [gprs] "=m" (__ti->pcpu_gprs),		\
			  [off] "=&r" (__off), [addr] "=&r" (__addr),	\
			  [ret] "=&r" (ret)				\
			: [pcpu_offset] "m" (__ti->pcpu_offset),	\
			  [pcp] "r" (pcp), [val] "r" ((u##sz)val)	\
			: "memory");					\
		return ret;						\
	}								\
									\
	asm volatile (__PCPU_GPRS_BEGIN					\
		"0: lr.w %[old], 0(%[addr])\n"				\
		"and %[new], %[old], %[inv_mask]\n"			\
		"or %[new], %[new], %[new_field]\n"			\
		"sc.w %[rc], %[new], 0(%[addr])\n"			\
		"bnez %[rc], 0b\n"					\
		__PCPU_GPRS_END						\
		: [gprs] "=m" (__ti->pcpu_gprs),			\
		  [off] "=&r" (__off), [addr] "=&r" (__addr),		\
		  [old] "=&r" (old), [new] "=&r" (new), [rc] "=&r" (rc)	\
		: [pcpu_offset] "m" (__ti->pcpu_offset),		\
		  [pcp] "r" (pcp32), [inv_mask] "r" (~mask),		\
		  [new_field] "r" (new_field)				\
		: "memory");						\
									\
	return (old & mask) >> shift;					\
}

__PERCPU_8_16_XCHG_CASE(8, .b)
__PERCPU_8_16_XCHG_CASE(16, .h)

#define __PERCPU_CMPXCHG_CASE(sz, lr_sfx, sc_sfx, cas_sfx)		\
static __always_inline unsigned long					\
__percpu_cmpxchg_case_##sz(void __percpu *pcp, unsigned long old,	\
			   unsigned long new)				\
{									\
	__PCPU_OP_CONTEXT();						\
	const long cmp = (long)(s##sz)(u##sz)old;			\
	unsigned long rc;						\
	u##sz ret = (u##sz)old;						\
									\
	if (IS_ENABLED(CONFIG_RISCV_ISA_ZACAS) &&			\
	    IS_ENABLED(CONFIG_TOOLCHAIN_HAS_ZACAS) &&			\
	    riscv_has_extension_unlikely(RISCV_ISA_EXT_ZACAS)) {	\
		asm volatile (__PCPU_GPRS_BEGIN				\
			".option push\n"				\
			".option arch, +zacas\n"			\
			"amocas" #cas_sfx " %[ret], %[new], 0(%[addr])\n"	\
			".option pop\n"					\
			__PCPU_GPRS_END					\
			: [gprs] "=m" (__ti->pcpu_gprs),		\
			  [off] "=&r" (__off), [addr] "=&r" (__addr),	\
			  [ret] "+&r" (ret)				\
			: [pcpu_offset] "m" (__ti->pcpu_offset),	\
			  [pcp] "r" (pcp), [new] "r" ((u##sz)new)	\
			: "memory");					\
	} else {							\
		asm volatile (__PCPU_GPRS_BEGIN				\
			"0: lr" #lr_sfx " %[ret], 0(%[addr])\n"		\
			"bne %[ret], %[old], 1f\n"			\
			"sc" #sc_sfx " %[rc], %[new], 0(%[addr])\n"	\
			"bnez %[rc], 0b\n"				\
			"1:\n"						\
			__PCPU_GPRS_END					\
			: [gprs] "=m" (__ti->pcpu_gprs),		\
			  [off] "=&r" (__off), [addr] "=&r" (__addr),	\
			  [ret] "=&r" (ret), [rc] "=&r" (rc)		\
			: [pcpu_offset] "m" (__ti->pcpu_offset),	\
			  [pcp] "r" (pcp), [old] "r" (cmp),		\
			  [new] "r" ((u##sz)new)			\
			: "memory");					\
	}								\
									\
	return ret;							\
}

__PERCPU_CMPXCHG_CASE(32, .w, .w, .w)
#ifdef CONFIG_64BIT
__PERCPU_CMPXCHG_CASE(64, .d, .d, .d)
#endif

/*
 * Use XLEN-wide masks to clear the upper bits of an RV64 sign-extended
 * LR.W result before comparing a high byte or halfword.
 */
#define __PERCPU_8_16_CMPXCHG_CASE(sz, sfx)				\
static __always_inline unsigned long					\
__percpu_cmpxchg_case_##sz(void __percpu *pcp, unsigned long old,	\
			   unsigned long new)				\
{									\
	__PCPU_OP_CONTEXT();						\
	const unsigned long shift = PERCPU_8_16_GET_SHIFT(pcp);		\
	const unsigned long field_mask = PERCPU_8_16_GET_MASK(sz);	\
	const unsigned long mask = field_mask << shift;			\
	const unsigned long old_field = (old & field_mask) << shift;	\
	const unsigned long new_field = (new & field_mask) << shift;	\
	void __percpu *pcp32 = PERCPU_8_16_GET_PCP32(pcp);		\
	unsigned long ret32, tmp, rc;					\
	u##sz ret = (u##sz)old;						\
									\
	if (IS_ENABLED(CONFIG_RISCV_ISA_ZABHA) &&			\
	    IS_ENABLED(CONFIG_RISCV_ISA_ZACAS) &&			\
	    IS_ENABLED(CONFIG_TOOLCHAIN_HAS_ZACAS) &&			\
	    riscv_has_extension_unlikely(RISCV_ISA_EXT_ZABHA) &&	\
	    riscv_has_extension_unlikely(RISCV_ISA_EXT_ZACAS)) {	\
		asm volatile (__PCPU_GPRS_BEGIN				\
			".option push\n"				\
			".option arch, +zacas, +zabha\n"		\
			"amocas" #sfx " %[ret], %[new], 0(%[addr])\n"	\
			".option pop\n"					\
			__PCPU_GPRS_END					\
			: [gprs] "=m" (__ti->pcpu_gprs),		\
			  [off] "=&r" (__off), [addr] "=&r" (__addr),	\
			  [ret] "+&r" (ret)				\
			: [pcpu_offset] "m" (__ti->pcpu_offset),	\
			  [pcp] "r" (pcp), [new] "r" ((u##sz)new)	\
			: "memory");					\
	} else {							\
		asm volatile (__PCPU_GPRS_BEGIN				\
			"0: lr.w %[ret], 0(%[addr])\n"			\
			"and %[tmp], %[ret], %[mask]\n"			\
			"bne %[tmp], %[old], 1f\n"			\
			"and %[tmp], %[ret], %[inv_mask]\n"		\
			"or %[tmp], %[tmp], %[new]\n"			\
			"sc.w %[rc], %[tmp], 0(%[addr])\n"		\
			"bnez %[rc], 0b\n"				\
			"1:\n"						\
			__PCPU_GPRS_END					\
			: [gprs] "=m" (__ti->pcpu_gprs),		\
			  [off] "=&r" (__off), [addr] "=&r" (__addr),	\
			  [ret] "=&r" (ret32), [tmp] "=&r" (tmp),	\
			  [rc] "=&r" (rc)				\
			: [pcpu_offset] "m" (__ti->pcpu_offset),	\
			  [pcp] "r" (pcp32), [mask] "r" (mask),		\
			  [old] "r" (old_field),			\
			  [new] "r" (new_field),			\
			  [inv_mask] "r" (~mask)			\
			: "memory");					\
									\
		ret = (ret32 & mask) >> shift;				\
	}								\
									\
	return ret;							\
}

__PERCPU_8_16_CMPXCHG_CASE(8, .b)
__PERCPU_8_16_CMPXCHG_CASE(16, .h)
#define _pcp_wrap(op, pcp, ...)						\
({									\
	op(&(pcp), __VA_ARGS__);					\
})

#define _pcp_wrap_return(op, pcp, args...)				\
({									\
	__auto_type __pcp_ptr = &(pcp);					\
									\
	(TYPEOF_UNQUAL(*__pcp_ptr))op(__pcp_ptr, ##args);		\
})

#define _pcp_wrap_xchg(op, pcp, val)					\
({									\
	__auto_type __pcp_ptr = &(pcp);					\
									\
	(TYPEOF_UNQUAL(*__pcp_ptr))op(__pcp_ptr,			\
					     (unsigned long)(val));	\
})

#define _pcp_wrap_cmpxchg(op, pcp, old, new)				\
({									\
	__auto_type __pcp_ptr = &(pcp);					\
									\
	(TYPEOF_UNQUAL(*__pcp_ptr))op(__pcp_ptr,			\
					     (unsigned long)(old),	\
					     (unsigned long)(new));	\
})

#define this_cpu_read_1(pcp)	_pcp_wrap_return(__percpu_read_8, pcp)
#define this_cpu_read_2(pcp)	_pcp_wrap_return(__percpu_read_16, pcp)
#define this_cpu_read_4(pcp)	_pcp_wrap_return(__percpu_read_32, pcp)

#ifdef CONFIG_64BIT
#define this_cpu_read_8(pcp)	_pcp_wrap_return(__percpu_read_64, pcp)
#endif

#define this_cpu_write_1(pcp, val)					\
	_pcp_wrap(__percpu_write_8, pcp, (unsigned long)(val))
#define this_cpu_write_2(pcp, val)					\
	_pcp_wrap(__percpu_write_16, pcp, (unsigned long)(val))
#define this_cpu_write_4(pcp, val)					\
	_pcp_wrap(__percpu_write_32, pcp, (unsigned long)(val))

#ifdef CONFIG_64BIT
#define this_cpu_write_8(pcp, val)					\
	_pcp_wrap(__percpu_write_64, pcp, (unsigned long)(val))
#endif

#define this_cpu_add_1(pcp, val)	_pcp_wrap(__percpu_add_amo_case_8, pcp, val)
#define this_cpu_add_2(pcp, val)	_pcp_wrap(__percpu_add_amo_case_16, pcp, val)
#define this_cpu_add_4(pcp, val)	_pcp_wrap(__percpu_add_amo_case_32, pcp, val)
#ifdef CONFIG_64BIT
#define this_cpu_add_8(pcp, val)	_pcp_wrap(__percpu_add_amo_case_64, pcp, val)
#endif

#define this_cpu_and_1(pcp, val)	_pcp_wrap(__percpu_and_amo_case_8, pcp, val)
#define this_cpu_and_2(pcp, val)	_pcp_wrap(__percpu_and_amo_case_16, pcp, val)
#define this_cpu_and_4(pcp, val)	_pcp_wrap(__percpu_and_amo_case_32, pcp, val)
#ifdef CONFIG_64BIT
#define this_cpu_and_8(pcp, val)	_pcp_wrap(__percpu_and_amo_case_64, pcp, val)
#endif

#define this_cpu_or_1(pcp, val)		_pcp_wrap(__percpu_or_amo_case_8, pcp, val)
#define this_cpu_or_2(pcp, val)		_pcp_wrap(__percpu_or_amo_case_16, pcp, val)
#define this_cpu_or_4(pcp, val)		_pcp_wrap(__percpu_or_amo_case_32, pcp, val)
#ifdef CONFIG_64BIT
#define this_cpu_or_8(pcp, val)		_pcp_wrap(__percpu_or_amo_case_64, pcp, val)
#endif

#define this_cpu_add_return_1(pcp, val)					\
	_pcp_wrap_return(__percpu_add_return_amo_case_8, pcp, val)
#define this_cpu_add_return_2(pcp, val)					\
	_pcp_wrap_return(__percpu_add_return_amo_case_16, pcp, val)
#define this_cpu_add_return_4(pcp, val)					\
	_pcp_wrap_return(__percpu_add_return_amo_case_32, pcp, val)
#ifdef CONFIG_64BIT
#define this_cpu_add_return_8(pcp, val)					\
	_pcp_wrap_return(__percpu_add_return_amo_case_64, pcp, val)
#endif

#define this_cpu_xchg_1(pcp, val)	_pcp_wrap_xchg(__percpu_xchg_case_8, pcp, val)
#define this_cpu_xchg_2(pcp, val)	_pcp_wrap_xchg(__percpu_xchg_case_16, pcp, val)
#define this_cpu_xchg_4(pcp, val)	_pcp_wrap_xchg(__percpu_xchg_case_32, pcp, val)
#ifdef CONFIG_64BIT
#define this_cpu_xchg_8(pcp, val)	_pcp_wrap_xchg(__percpu_xchg_case_64, pcp, val)
#endif

#define this_cpu_cmpxchg_1(pcp, o, n)					\
	_pcp_wrap_cmpxchg(__percpu_cmpxchg_case_8, pcp, o, n)
#define this_cpu_cmpxchg_2(pcp, o, n)					\
	_pcp_wrap_cmpxchg(__percpu_cmpxchg_case_16, pcp, o, n)
#define this_cpu_cmpxchg_4(pcp, o, n)					\
	_pcp_wrap_cmpxchg(__percpu_cmpxchg_case_32, pcp, o, n)
#ifdef CONFIG_64BIT
#define this_cpu_cmpxchg_8(pcp, o, n)					\
	_pcp_wrap_cmpxchg(__percpu_cmpxchg_case_64, pcp, o, n)
#define this_cpu_cmpxchg64(pcp, o, n)	this_cpu_cmpxchg_8(pcp, o, n)
#endif

#undef PERCPU_RW_OPS
#undef __PERCPU_AMO_OP_CASE
#undef __PERCPU_8_16_OP_CASE
#undef __PERCPU_XCHG_AMO_CASE
#undef __PERCPU_8_16_XCHG_CASE
#undef __PERCPU_CMPXCHG_CASE
#undef __PERCPU_8_16_CMPXCHG_CASE
#undef PERCPU_8_16_GET_SHIFT
#undef PERCPU_8_16_GET_MASK
#undef PERCPU_8_16_GET_PCP32
#undef __PCPU_OP_CONTEXT

#include <asm-generic/percpu.h>

#endif /* __ASM_PERCPU_H */
