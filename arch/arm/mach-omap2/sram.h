/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Interface for functions that need to be run in internal SRAM
 */

#ifndef __ASSEMBLY__

extern void omap3_sram_restore_context(void);

extern int __init omap_sram_init(void);

extern void *omap_sram_push(void *funcp, unsigned long size);

#ifdef CONFIG_PM
extern void omap_push_sram_idle(void);
#else
static inline void omap_push_sram_idle(void) {}
#endif /* CONFIG_PM */

#endif /* __ASSEMBLY__ */

/*
 * OMAP2+: define the SRAM PA addresses.
 * Used by the SRAM management code and the idle sleep code.
 */
#define OMAP3_SRAM_PA           0x40200000
