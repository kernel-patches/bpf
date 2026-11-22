/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Author: Patrick Stählin <me@packi.ch>
 */
#include <linux/linkage.h>

#include <asm/asm.h>
#include <asm/asm-offsets.h>

	.text
	.altmacro

	.macro save_all_base_regs
	REG_S x1,  PT_RA(sp)
	REG_S x3,  PT_GP(sp)
	REG_S x4,  PT_TP(sp)
	REG_S x5,  PT_T0(sp)
	REG_S x6,  PT_T1(sp)
	REG_S x7,  PT_T2(sp)
	REG_S x8,  PT_S0(sp)
	REG_S x9,  PT_S1(sp)
	REG_S x10, PT_A0(sp)
	REG_S x11, PT_A1(sp)
	REG_S x12, PT_A2(sp)
	REG_S x13, PT_A3(sp)
	REG_S x14, PT_A4(sp)
	REG_S x15, PT_A5(sp)
	REG_S x16, PT_A6(sp)
	REG_S x17, PT_A7(sp)
	REG_S x18, PT_S2(sp)
	REG_S x19, PT_S3(sp)
	REG_S x20, PT_S4(sp)
	REG_S x21, PT_S5(sp)
	REG_S x22, PT_S6(sp)
	REG_S x23, PT_S7(sp)
	REG_S x24, PT_S8(sp)
	REG_S x25, PT_S9(sp)
	REG_S x26, PT_S10(sp)
	REG_S x27, PT_S11(sp)
	REG_S x28, PT_T3(sp)
	REG_S x29, PT_T4(sp)
	REG_S x30, PT_T5(sp)
	REG_S x31, PT_T6(sp)
	/* save original sp */
	addi a0, sp, PT_SIZE_ON_STACK
	REG_S a0, PT_SP(sp)
	.endm

	.macro restore_all_base_regs
	REG_L x3,  PT_GP(sp)
	REG_L x4,  PT_TP(sp)
	REG_L x5,  PT_T0(sp)
	REG_L x6,  PT_T1(sp)
	REG_L x7,  PT_T2(sp)
	REG_L x8,  PT_S0(sp)
	REG_L x9,  PT_S1(sp)
	REG_L x10, PT_A0(sp)
	REG_L x11, PT_A1(sp)
	REG_L x12, PT_A2(sp)
	REG_L x13, PT_A3(sp)
	REG_L x14, PT_A4(sp)
	REG_L x15, PT_A5(sp)
	REG_L x16, PT_A6(sp)
	REG_L x17, PT_A7(sp)
	REG_L x18, PT_S2(sp)
	REG_L x19, PT_S3(sp)
	REG_L x20, PT_S4(sp)
	REG_L x21, PT_S5(sp)
	REG_L x22, PT_S6(sp)
	REG_L x23, PT_S7(sp)
	REG_L x24, PT_S8(sp)
	REG_L x25, PT_S9(sp)
	REG_L x26, PT_S10(sp)
	REG_L x27, PT_S11(sp)
	REG_L x28, PT_T3(sp)
	REG_L x29, PT_T4(sp)
	REG_L x30, PT_T5(sp)
	REG_L x31, PT_T6(sp)
	.endm

/*
 * Under CONFIG_UNWINDER_DWARF_CFI, PT_EPC(sp) is seeded with
 * &arch_rethook_trampoline before rethook_trampoline_handler() overwrites
 * regs->epc with the restored caller PC prior to running rethook handlers,
 * enabling reliable CFI unwinding across kretprobe and fprobe return hooks.
 */
SYM_CODE_START(arch_rethook_trampoline)
#ifdef CONFIG_UNWINDER_DWARF_CFI
	.cfi_startproc
#endif
	addi sp, sp, -(PT_SIZE_ON_STACK)
#ifdef CONFIG_UNWINDER_DWARF_CFI
	.cfi_def_cfa_offset PT_SIZE_ON_STACK
#endif
	save_all_base_regs
#ifdef CONFIG_UNWINDER_DWARF_CFI
	.cfi_offset s0, PT_S0 - PT_SIZE_ON_STACK
	la t0, arch_rethook_trampoline
	REG_S t0, PT_EPC(sp)
	.cfi_offset ra, PT_EPC - PT_SIZE_ON_STACK
#endif

	move a0, sp /* pt_regs */

	call arch_rethook_trampoline_callback

	/* use the result as the return-address */
	move ra, a0
#ifdef CONFIG_UNWINDER_DWARF_CFI
	.cfi_same_value ra
#endif

	restore_all_base_regs
#ifdef CONFIG_UNWINDER_DWARF_CFI
	.cfi_restore s0
#endif
	addi sp, sp, PT_SIZE_ON_STACK
#ifdef CONFIG_UNWINDER_DWARF_CFI
	.cfi_def_cfa_offset 0
#endif

	ret
#ifdef CONFIG_UNWINDER_DWARF_CFI
	.cfi_endproc
#endif
SYM_CODE_END(arch_rethook_trampoline)
