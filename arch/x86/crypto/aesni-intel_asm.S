/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Implement AES algorithm in Intel AES-NI instructions.
 *
 * The white paper of AES-NI instructions can be downloaded from:
 *   http://softwarecommunity.intel.com/isn/downloads/intelavx/AES-Instructions-Set_WP.pdf
 *
 * Copyright (C) 2008, Intel Corp.
 *    Author: Huang Ying <ying.huang@intel.com>
 *            Vinodh Gopal <vinodh.gopal@intel.com>
 *            Kahraman Akdemir
 *
 * Copyright (c) 2010, Intel Corporation.
 *
 * Ported x86_64 version to x86:
 *    Author: Mathias Krause <minipli@googlemail.com>
 */

#include <linux/linkage.h>
#include <linux/objtool.h>
#include <asm/frame.h>

#ifdef __x86_64__
#define AREG	%rax
#define KEYP	%rdi
#define OUTP	%rsi
#define UKEYP	OUTP
#define T1	%r10
#define TKEYP	T1
#define T2	%r11
#else
#define AREG	%eax
#define KEYP	%edi
#define OUTP	AREG
#define UKEYP	OUTP
#define T1	%ecx
#define TKEYP	T1
#endif

SYM_FUNC_START_LOCAL(_key_expansion_256a)
	pshufd $0b11111111, %xmm1, %xmm1
	shufps $0b00010000, %xmm0, %xmm4
	pxor %xmm4, %xmm0
	shufps $0b10001100, %xmm0, %xmm4
	pxor %xmm4, %xmm0
	pxor %xmm1, %xmm0
	movaps %xmm0, (TKEYP)
	add $0x10, TKEYP
	RET
SYM_FUNC_END(_key_expansion_256a)
SYM_FUNC_ALIAS_LOCAL(_key_expansion_128, _key_expansion_256a)

SYM_FUNC_START_LOCAL(_key_expansion_192a)
	pshufd $0b01010101, %xmm1, %xmm1
	shufps $0b00010000, %xmm0, %xmm4
	pxor %xmm4, %xmm0
	shufps $0b10001100, %xmm0, %xmm4
	pxor %xmm4, %xmm0
	pxor %xmm1, %xmm0

	movaps %xmm2, %xmm5
	movaps %xmm2, %xmm6
	pslldq $4, %xmm5
	pshufd $0b11111111, %xmm0, %xmm3
	pxor %xmm3, %xmm2
	pxor %xmm5, %xmm2

	movaps %xmm0, %xmm1
	shufps $0b01000100, %xmm0, %xmm6
	movaps %xmm6, (TKEYP)
	shufps $0b01001110, %xmm2, %xmm1
	movaps %xmm1, 0x10(TKEYP)
	add $0x20, TKEYP
	RET
SYM_FUNC_END(_key_expansion_192a)

SYM_FUNC_START_LOCAL(_key_expansion_192b)
	pshufd $0b01010101, %xmm1, %xmm1
	shufps $0b00010000, %xmm0, %xmm4
	pxor %xmm4, %xmm0
	shufps $0b10001100, %xmm0, %xmm4
	pxor %xmm4, %xmm0
	pxor %xmm1, %xmm0

	movaps %xmm2, %xmm5
	pslldq $4, %xmm5
	pshufd $0b11111111, %xmm0, %xmm3
	pxor %xmm3, %xmm2
	pxor %xmm5, %xmm2

	movaps %xmm0, (TKEYP)
	add $0x10, TKEYP
	RET
SYM_FUNC_END(_key_expansion_192b)

SYM_FUNC_START_LOCAL(_key_expansion_256b)
	pshufd $0b10101010, %xmm1, %xmm1
	shufps $0b00010000, %xmm2, %xmm4
	pxor %xmm4, %xmm2
	shufps $0b10001100, %xmm2, %xmm4
	pxor %xmm4, %xmm2
	pxor %xmm1, %xmm2
	movaps %xmm2, (TKEYP)
	add $0x10, TKEYP
	RET
SYM_FUNC_END(_key_expansion_256b)

/*
 * void aesni_set_key(struct crypto_aes_ctx *ctx, const u8 *in_key,
 *                    unsigned int key_len)
 */
SYM_FUNC_START(aesni_set_key)
	FRAME_BEGIN
#ifndef __x86_64__
	pushl KEYP
	movl (FRAME_OFFSET+8)(%esp), KEYP	# ctx
	movl (FRAME_OFFSET+12)(%esp), UKEYP	# in_key
	movl (FRAME_OFFSET+16)(%esp), %edx	# key_len
#endif
	movups (UKEYP), %xmm0		# user key (first 16 bytes)
	movaps %xmm0, (KEYP)
	lea 0x10(KEYP), TKEYP		# key addr
	movl %edx, 480(KEYP)
	pxor %xmm4, %xmm4		# xmm4 is assumed 0 in _key_expansion_x
	cmp $24, %dl
	jb .Lenc_key128
	je .Lenc_key192
	movups 0x10(UKEYP), %xmm2	# other user key
	movaps %xmm2, (TKEYP)
	add $0x10, TKEYP
	aeskeygenassist $0x1, %xmm2, %xmm1	# round 1
	call _key_expansion_256a
	aeskeygenassist $0x1, %xmm0, %xmm1
	call _key_expansion_256b
	aeskeygenassist $0x2, %xmm2, %xmm1	# round 2
	call _key_expansion_256a
	aeskeygenassist $0x2, %xmm0, %xmm1
	call _key_expansion_256b
	aeskeygenassist $0x4, %xmm2, %xmm1	# round 3
	call _key_expansion_256a
	aeskeygenassist $0x4, %xmm0, %xmm1
	call _key_expansion_256b
	aeskeygenassist $0x8, %xmm2, %xmm1	# round 4
	call _key_expansion_256a
	aeskeygenassist $0x8, %xmm0, %xmm1
	call _key_expansion_256b
	aeskeygenassist $0x10, %xmm2, %xmm1	# round 5
	call _key_expansion_256a
	aeskeygenassist $0x10, %xmm0, %xmm1
	call _key_expansion_256b
	aeskeygenassist $0x20, %xmm2, %xmm1	# round 6
	call _key_expansion_256a
	aeskeygenassist $0x20, %xmm0, %xmm1
	call _key_expansion_256b
	aeskeygenassist $0x40, %xmm2, %xmm1	# round 7
	call _key_expansion_256a
	jmp .Ldec_key
.Lenc_key192:
	movq 0x10(UKEYP), %xmm2		# other user key
	aeskeygenassist $0x1, %xmm2, %xmm1	# round 1
	call _key_expansion_192a
	aeskeygenassist $0x2, %xmm2, %xmm1	# round 2
	call _key_expansion_192b
	aeskeygenassist $0x4, %xmm2, %xmm1	# round 3
	call _key_expansion_192a
	aeskeygenassist $0x8, %xmm2, %xmm1	# round 4
	call _key_expansion_192b
	aeskeygenassist $0x10, %xmm2, %xmm1	# round 5
	call _key_expansion_192a
	aeskeygenassist $0x20, %xmm2, %xmm1	# round 6
	call _key_expansion_192b
	aeskeygenassist $0x40, %xmm2, %xmm1	# round 7
	call _key_expansion_192a
	aeskeygenassist $0x80, %xmm2, %xmm1	# round 8
	call _key_expansion_192b
	jmp .Ldec_key
.Lenc_key128:
	aeskeygenassist $0x1, %xmm0, %xmm1	# round 1
	call _key_expansion_128
	aeskeygenassist $0x2, %xmm0, %xmm1	# round 2
	call _key_expansion_128
	aeskeygenassist $0x4, %xmm0, %xmm1	# round 3
	call _key_expansion_128
	aeskeygenassist $0x8, %xmm0, %xmm1	# round 4
	call _key_expansion_128
	aeskeygenassist $0x10, %xmm0, %xmm1	# round 5
	call _key_expansion_128
	aeskeygenassist $0x20, %xmm0, %xmm1	# round 6
	call _key_expansion_128
	aeskeygenassist $0x40, %xmm0, %xmm1	# round 7
	call _key_expansion_128
	aeskeygenassist $0x80, %xmm0, %xmm1	# round 8
	call _key_expansion_128
	aeskeygenassist $0x1b, %xmm0, %xmm1	# round 9
	call _key_expansion_128
	aeskeygenassist $0x36, %xmm0, %xmm1	# round 10
	call _key_expansion_128
.Ldec_key:
	sub $0x10, TKEYP
	movaps (KEYP), %xmm0
	movaps (TKEYP), %xmm1
	movaps %xmm0, 240(TKEYP)
	movaps %xmm1, 240(KEYP)
	add $0x10, KEYP
	lea 240-16(TKEYP), UKEYP
.align 4
.Ldec_key_loop:
	movaps (KEYP), %xmm0
	aesimc %xmm0, %xmm1
	movaps %xmm1, (UKEYP)
	add $0x10, KEYP
	sub $0x10, UKEYP
	cmp TKEYP, KEYP
	jb .Ldec_key_loop
#ifndef __x86_64__
	popl KEYP
#endif
	FRAME_END
	RET
SYM_FUNC_END(aesni_set_key)
