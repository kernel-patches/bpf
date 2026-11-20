/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Cache error entry for the R10000, R12000, R14000 and R16000.
 *
 * Copyright (C) 2026 Imre Kaloz <kaloz@kernel.org>
 */
#include <asm/addrspace.h>
#include <asm/asm.h>
#include <asm/cacheops.h>
#include <asm/regdef.h>
#include <asm/mipsregs.h>
#include <asm/stackframe.h>

/*
 * Copied to the cache error vector and fetched uncached. Only k0 and k1
 * may be used here. An XKPHYS kernel may lie outside the 256MB region a j
 * from the vector reaches.
 */
	LEAF(except_vec2_r10k)
	.set	push
	.set	noreorder
	.set	noat
#if defined(CONFIG_64BIT) && VMLINUX_LOAD_ADDRESS >= XKPHYS && \
    VMLINUX_LOAD_ADDRESS < XKSEG
	PTR_LA	k0, cache_error_r10k
	PTR_LI	k1, TO_PHYS_MASK
	and	k0, k0, k1
	PTR_LI	k1, UNCAC_BASE
	or	k0, k0, k1
	jr	k0
	 nop
#else
	j	cache_error_r10k
	 nop
#endif
	.set	pop
	END(except_vec2_r10k)

/*
 * Entered uncached with ERL set. An I-cache error is cleared by rewriting
 * both ways of the set with zeroed tags and data of good parity. With EXL
 * clear the error becomes an ordinary exception at ErrorEPC, handled on
 * the kernel stack; with EXL set the interrupted handler's k0 and k1 are
 * lost and it is never resumed. ERL is cleared so the handler can take
 * exceptions.
 */
NESTED(cache_error_r10k, PT_SIZE, sp)
	.set	push
	.set	noreorder
	.set	noat
	mfc0	k0, CP0_CACHEERR
	srl	k1, k0, 30		/* I-cache */
	bnez	k1, 1f
	 andi	k0, k0, 0x3fc0		/* VA[13:6] */
	PTR_LI	k1, CKSEG0
	or	k0, k0, k1
	mtc0	zero, CP0_TAGLO
	mtc0	zero, CP0_TAGHI
	mtc0	zero, CP0_ECC
	cache	Index_Store_Tag_I, 0(k0)	/* VA[0] selects the way */
	cache	Index_Store_Tag_I, 1(k0)
3:	cache	Index_Store_Data_I, 0(k0)	/* VA[5:2] the word */
	cache	Index_Store_Data_I, 1(k0)
	PTR_ADDIU k0, 4
	andi	k1, k0, 0x3c
	bnez	k1, 3b
	 nop

1:	mfc0	k0, CP0_STATUS
	andi	k0, k0, ST0_EXL
	bnez	k0, 2f
	 nop
	MFC0	k0, CP0_ERROREPC
	MTC0	k0, CP0_EPC
	mfc0	k0, CP0_STATUS
	li	k1, ~ST0_ERL
	and	k0, k0, k1
	ori	k0, k0, ST0_EXL
	mtc0	k0, CP0_STATUS
	PTR_LA	k0, cache_error_r10k_resume
	jr	k0
	 nop

	/* Nothing may post another cache error while this one is fatal. */
2:	mfc0	k0, CP0_STATUS
	li	k1, ~ST0_ERL
	and	k0, k0, k1
	li	k1, ST0_DE
	or	k0, k0, k1
	mtc0	k0, CP0_STATUS
	PTR_LA	k0, cache_error_r10k_fatal
	jr	k0
	 nop
	.set	pop
	END(cache_error_r10k)

NESTED(cache_error_r10k_resume, PT_SIZE, sp)
	.cfi_signal_frame
	.set	push
	.set	noat
	SAVE_ALL
	CLI
	move	a0, sp
	li	a1, 1
	jal	do_cache_error_r10k
	RESTORE_TEMP
	RESTORE_STATIC
	RESTORE_AT
	RESTORE_SOME
	RESTORE_SP_AND_RET
	.set	pop
	END(cache_error_r10k_resume)

NESTED(cache_error_r10k_fatal, PT_SIZE, sp)
	.cfi_signal_frame
	.set	push
	.set	noat
	SAVE_ALL
	CLI
	move	a0, sp
	li	a1, 0
	jal	do_cache_error_r10k
	/* do_cache_error_r10k does not return when a1 is 0 */
	.set	pop
	END(cache_error_r10k_fatal)
