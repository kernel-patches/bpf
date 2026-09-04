/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_ARM64_CFI_H
#define _ASM_ARM64_CFI_H

#define __bpfcall

#ifdef CONFIG_CFI
static inline int cfi_get_offset(void)
{
	return 4 + 4 * CONFIG_ARM64_FUNCTION_PREFIX_NOPS;
}
#define cfi_get_offset cfi_get_offset
#endif /* CONFIG_CFI */

#endif /* _ASM_ARM64_CFI_H */
