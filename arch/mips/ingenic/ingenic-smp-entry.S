/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 Paul Burton <paulburton@kernel.org>
 * XBurst secondary CPU reset entry
 */

#include <asm/addrspace.h>
#include <asm/asm.h>
#include <asm/asmmacro.h>
#include <asm/cacheops.h>
#include <asm/mipsregs.h>

#define CACHE_SIZE	(32 * 1024)
#define CACHE_LINESIZE	32

	/* The CP0 REIM register only stores the upper 16 address bits. */
	.section .text.smp-entry, "ax"
	.balign 0x10000
	.set noreorder
LEAF(xburst_secondary_cpu_entry)
	mtc0	zero, CP0_CAUSE
	li	t0, ST0_CU0
	mtc0	t0, CP0_STATUS
	ehb

	/* Invalidate both private caches before entering cached code. */
	PTR_LI	t0, CKSEG0
	ori	t1, t0, CACHE_SIZE
	mtc0	zero, CP0_TAGLO
	ehb
1:	cache	Index_Store_Tag_I, 0(t0)
	cache	Index_Store_Tag_D, 0(t0)
	addiu	t0, t0, CACHE_LINESIZE
	bne	t0, t1, 1b
	 nop

	mfc0	t0, CP0_CONFIG
	li	t1, ~CONF_CM_CMASK
	and	t0, t0, t1
	ori	t0, t0, CONF_CM_CACHABLE_NONCOHERENT
	mtc0	t0, CP0_CONFIG
	mtc0	zero, CP0_PAGEMASK
	ehb

	/* CPU0 publishes these in RAM before releasing CPU1 from reset. */
	PTR_LA	t0, xburst_cpu_entry_sp
	LONG_L	sp, 0(t0)
	PTR_LA	t0, xburst_cpu_entry_gp
	LONG_L	gp, 0(t0)

	PTR_LA	t0, smp_bootstrap
	jr	t0
	 nop
END(xburst_secondary_cpu_entry)
