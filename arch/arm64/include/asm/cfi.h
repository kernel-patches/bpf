/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_ARM64_CFI_H
#define _ASM_ARM64_CFI_H

#include <asm/insn-def.h>

#define __bpfcall

#ifdef CONFIG_CFI
static inline int cfi_get_offset(void)
{
	/* The 4-byte type hash sits before the prefix NOPs. */
	return 4 + CONFIG_ARM64_FUNCTION_PREFIX_NOPS * AARCH64_INSN_SIZE;
}
#define cfi_get_offset cfi_get_offset
#endif /* CONFIG_CFI */

#endif /* _ASM_ARM64_CFI_H */
