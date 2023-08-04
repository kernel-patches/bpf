// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 Western Digital Corporation or its affiliates.
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/irq.h>
#include <linux/stringify.h>

#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/csr.h>
#include <asm/insn.h>
#include <asm/reg.h>

#define XLEN_MINUS_16			((__riscv_xlen) - 16)

#define DECLARE_UNPRIVILEGED_LOAD_FUNCTION(type, insn)			\
static inline type load_##type(const type *addr)			\
{									\
	type val;							\
	asm (#insn " %0, %1"						\
	: "=&r" (val) : "m" (*addr));					\
	return val;							\
}

#define DECLARE_UNPRIVILEGED_STORE_FUNCTION(type, insn)			\
static inline void store_##type(type *addr, type val)			\
{									\
	asm volatile (#insn " %0, %1\n"					\
	: : "r" (val), "m" (*addr));					\
}

DECLARE_UNPRIVILEGED_LOAD_FUNCTION(u8, lbu)
DECLARE_UNPRIVILEGED_LOAD_FUNCTION(u16, lhu)
DECLARE_UNPRIVILEGED_LOAD_FUNCTION(s8, lb)
DECLARE_UNPRIVILEGED_LOAD_FUNCTION(s16, lh)
DECLARE_UNPRIVILEGED_LOAD_FUNCTION(s32, lw)
DECLARE_UNPRIVILEGED_STORE_FUNCTION(u8, sb)
DECLARE_UNPRIVILEGED_STORE_FUNCTION(u16, sh)
DECLARE_UNPRIVILEGED_STORE_FUNCTION(u32, sw)
#if defined(CONFIG_64BIT)
DECLARE_UNPRIVILEGED_LOAD_FUNCTION(u32, lwu)
DECLARE_UNPRIVILEGED_LOAD_FUNCTION(u64, ld)
DECLARE_UNPRIVILEGED_STORE_FUNCTION(u64, sd)
DECLARE_UNPRIVILEGED_LOAD_FUNCTION(ulong, ld)
#else
DECLARE_UNPRIVILEGED_LOAD_FUNCTION(u32, lw)
DECLARE_UNPRIVILEGED_LOAD_FUNCTION(ulong, lw)

static inline u64 load_u64(const u64 *addr)
{
	return load_u32((u32 *)addr)
		+ ((u64)load_u32((u32 *)addr + 1) << 32);
}

static inline void store_u64(u64 *addr, u64 val)
{
	store_u32((u32 *)addr, val);
	store_u32((u32 *)addr + 1, val >> 32);
}
#endif

static inline ulong get_insn(ulong mepc)
{
	register ulong __mepc asm ("a2") = mepc;
	ulong val, rvc_mask = 3, tmp;

	asm ("and %[tmp], %[addr], 2\n"
		"bnez %[tmp], 1f\n"
#if defined(CONFIG_64BIT)
		__stringify(LWU) " %[insn], (%[addr])\n"
#else
		__stringify(LW) " %[insn], (%[addr])\n"
#endif
		"and %[tmp], %[insn], %[rvc_mask]\n"
		"beq %[tmp], %[rvc_mask], 2f\n"
		"sll %[insn], %[insn], %[xlen_minus_16]\n"
		"srl %[insn], %[insn], %[xlen_minus_16]\n"
		"j 2f\n"
		"1:\n"
		"lhu %[insn], (%[addr])\n"
		"and %[tmp], %[insn], %[rvc_mask]\n"
		"bne %[tmp], %[rvc_mask], 2f\n"
		"lhu %[tmp], 2(%[addr])\n"
		"sll %[tmp], %[tmp], 16\n"
		"add %[insn], %[insn], %[tmp]\n"
		"2:"
	: [insn] "=&r" (val), [tmp] "=&r" (tmp)
	: [addr] "r" (__mepc), [rvc_mask] "r" (rvc_mask),
	  [xlen_minus_16] "i" (XLEN_MINUS_16));

	return val;
}

union reg_data {
	u8 data_bytes[8];
	ulong data_ulong;
	u64 data_u64;
};

int handle_misaligned_load(struct pt_regs *regs)
{
	union reg_data val;
	unsigned long epc = regs->epc;
	unsigned long insn = get_insn(epc);
	unsigned long addr = csr_read(mtval);
	int i, fp = 0, shift = 0, len = 0;

	regs->epc = 0;

	if (riscv_insn_is_lw(insn)) {
		len = 4;
		shift = 8 * (sizeof(unsigned long) - len);
#if defined(CONFIG_64BIT)
	} else if (riscv_insn_is_ld(insn)) {
		len = 8;
		shift = 8 * (sizeof(unsigned long) - len);
	} else if (riscv_insn_is_lwu(insn)) {
		len = 4;
#endif
	} else if (riscv_insn_is_fld(insn)) {
		fp = 1;
		len = 8;
	} else if (riscv_insn_is_flw(insn)) {
		fp = 1;
		len = 4;
	} else if (riscv_insn_is_lh(insn)) {
		len = 2;
		shift = 8 * (sizeof(unsigned long) - len);
	} else if (riscv_insn_is_lhu(insn)) {
		len = 2;
#if defined(CONFIG_64BIT)
	} else if (riscv_insn_is_c_ld(insn)) {
		len = 8;
		shift = 8 * (sizeof(unsigned long) - len);
		insn = riscv_insn_extract_csca_rs2(insn);
	} else if (riscv_insn_is_c_ldsp(insn) && (RVC_RD_CI(insn))) {
		len = 8;
		shift = 8 * (sizeof(unsigned long) - len);
#endif
	} else if (riscv_insn_is_c_lw(insn)) {
		len = 4;
		shift = 8 * (sizeof(unsigned long) - len);
		insn = riscv_insn_extract_csca_rs2(insn);
	} else if (riscv_insn_is_c_lwsp(insn) && (RVC_RD_CI(insn))) {
		len = 4;
		shift = 8 * (sizeof(unsigned long) - len);
	} else if (riscv_insn_is_c_fld(insn)) {
		fp = 1;
		len = 8;
		insn = riscv_insn_extract_csca_rs2(insn);
	} else if (riscv_insn_is_c_fldsp(insn)) {
		fp = 1;
		len = 8;
#if defined(CONFIG_32BIT)
	} else if (riscv_insn_is_c_flw(insn)) {
		fp = 1;
		len = 4;
		insn = riscv_insn_extract_csca_rs2(insn);
	} else if (riscv_insn_is_c_flwsp(insn)) {
		fp = 1;
		len = 4;
#endif
	} else {
		regs->epc = epc;
		return -1;
	}

	val.data_u64 = 0;
	for (i = 0; i < len; i++)
		val.data_bytes[i] = load_u8((void *)(addr + i));

	if (fp)
		return -1;
	rv_insn_reg_set_val((unsigned long *)regs, RV_EXTRACT_RD_REG(insn),
			    val.data_ulong << shift >> shift);

	regs->epc = epc + INSN_LEN(insn);

	return 0;
}

int handle_misaligned_store(struct pt_regs *regs)
{
	union reg_data val;
	unsigned long epc = regs->epc;
	unsigned long insn = get_insn(epc);
	unsigned long addr = csr_read(mtval);
	int i, len = 0;

	regs->epc = 0;

	rv_insn_reg_get_val((unsigned long *)regs, riscv_insn_extract_rs2(insn),
			    &val.data_ulong);

	if (riscv_insn_is_sw(insn)) {
		len = 4;
#if defined(CONFIG_64BIT)
	} else if (riscv_insn_is_sd(insn)) {
		len = 8;
#endif
	} else if (riscv_insn_is_sh(insn)) {
		len = 2;
#if defined(CONFIG_64BIT)
	} else if (riscv_insn_is_c_sd(insn)) {
		len = 8;
		rv_insn_reg_get_val((unsigned long *)regs,
				    riscv_insn_extract_cr_rs2(insn),
				    &val.data_ulong);
	} else if (riscv_insn_is_c_sdsp(insn)) {
		len = 8;
		rv_insn_reg_get_val((unsigned long *)regs,
				    riscv_insn_extract_csca_rs2(insn),
				    &val.data_ulong);
#endif
	} else if (riscv_insn_is_c_sw(insn)) {
		len = 4;
		rv_insn_reg_get_val((unsigned long *)regs,
				    riscv_insn_extract_cr_rs2(insn),
				    &val.data_ulong);
	} else if (riscv_insn_is_c_swsp(insn)) {
		len = 4;
		rv_insn_reg_get_val((unsigned long *)regs,
				    riscv_insn_extract_csca_rs2(insn),
				    &val.data_ulong);
	} else {
		regs->epc = epc;
		return -1;
	}

	for (i = 0; i < len; i++)
		store_u8((void *)(addr + i), val.data_bytes[i]);

	regs->epc = epc + INSN_LEN(insn);

	return 0;
}
