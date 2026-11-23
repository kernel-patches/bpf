########################################################################
# Implement fast SHA-512 with AVX2 instructions. (x86_64)
#
# Copyright (C) 2013 Intel Corporation.
# Copyright 2026 Google LLC
#
# Authors:
#     James Guilford <james.guilford@intel.com>
#     Kirk Yap <kirk.s.yap@intel.com>
#     David Cote <david.m.cote@intel.com>
#     Tim Chen <tim.c.chen@linux.intel.com>
#
# This software is available to you under a choice of one of two
# licenses.  You may choose to be licensed under the terms of the GNU
# General Public License (GPL) Version 2, available from the file
# COPYING in the main directory of this source tree, or the
# OpenIB.org BSD license below:
#
#     Redistribution and use in source and binary forms, with or
#     without modification, are permitted provided that the following
#     conditions are met:
#
#      - Redistributions of source code must retain the above
#        copyright notice, this list of conditions and the following
#        disclaimer.
#
#      - Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials
#        provided with the distribution.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
########################################################################
#
# This code is described in an Intel White-Paper:
# "Fast SHA-512 Implementations on Intel Architecture Processors"
#
# To find it, surf to http://www.intel.com/p/en_US/embedded
# and search for that title.
#
########################################################################

#include <linux/linkage.h>

.text

# Rolling window of 16 scheduled message words W[t-16..t-1]
Y_0 = %ymm4
Y_1 = %ymm5
Y_2 = %ymm6
Y_3 = %ymm7
X_0 = %xmm4
X_1 = %xmm5
X_2 = %xmm6
X_3 = %xmm7

YTMP0 = %ymm0
YTMP1 = %ymm1
YTMP2 = %ymm2
YTMP3 = %ymm3
YTMP4 = %ymm8
XTMP1 = %xmm1
XTMP2 = %xmm2
XTMP3 = %xmm3
XTMP4 = %xmm8
XFER  = YTMP0
YBSWAP = %ymm9
YROR8 = %ymm10

# 1st arg is %rdi, which is saved to the stack and accessed later via %r12
CTX1        = %rdi
CTX2        = %r12
# 2nd arg
INP         = %rsi
# 3rd arg
NUM_BLKS    = %rdx

c           = %rcx
d           = %r8
e           = %rdx

TBL   = %rdi # clobbers CTX1

a     = %rax
b     = %rbx

f     = %r9
g     = %r10
h     = %r11

T1    = %r12 # clobbers CTX2
y0    = %r13
y1    = %r14
y2    = %r15

# Local variables (stack frame)
XFER_SIZE = 4*8
SRND_SIZE = 1*8
INPEND_SIZE = 1*8
CTX_SIZE = 1*8

frame_XFER = 0
frame_SRND = frame_XFER + XFER_SIZE
frame_INPEND = frame_SRND + SRND_SIZE
frame_CTX = frame_INPEND + INPEND_SIZE
frame_size = frame_CTX + CTX_SIZE

# addm [mem], reg
# Add reg to mem using reg-mem add and store
.macro addm p1 p2
	add	\p1, \p2
	mov	\p2, \p1
.endm

# rotate_Ys
# Rotate values of symbols Y_0..Y_3 and X_0..X_3
.macro rotate_Ys
	Y_  = Y_0
	Y_0 = Y_1
	Y_1 = Y_2
	Y_2 = Y_3
	Y_3 = Y_
	X_  = X_0
	X_0 = X_1
	X_1 = X_2
	X_2 = X_3
	X_3 = X_
.endm

# RotateState
.macro RotateState
	# Rotate symbols a..h right
	TMP_   = h
	h      = g
	g      = f
	f      = e
	e      = d
	d      = c
	c      = b
	b      = a
	a      = TMP_
.endm

# macro MY_VPALIGNR	YDST, YSRC1, YSRC2, RVAL
# YDST = {YSRC1, YSRC2} >> RVAL*8
.macro MY_VPALIGNR YDST YSRC1 YSRC2 RVAL
	vperm2i128	$0x3, \YSRC2, \YSRC1, \YDST	# YDST = {YSRC1_LO, YSRC2_HI}
	vpalignr	$\RVAL, \YSRC2, \YDST, \YDST	# YDST = {YSRC1, YSRC2} >> RVAL*8
.endm

# Do one SHA-512 round using the state a-h and \wk = W[t] + K[t].  Updates a-h
# and rotates their aliases to match what the next round expects.
.macro SHA512_Round wk
	add	\wk, h		# h = h + w + k
	mov	f, y2		# y2 = f
	rorx	$41, e, y0	# y0 = e ror 41
	rorx	$18, e, y1	# y1 = e ror 18
	xor	g, y2		# y2 = f ^ g

	xor	y1, y0		# y0 = (e ror 41) ^ (e ror 18)
	rorx	$14, e, y1	# y1 = e ror 14
	and	e, y2		# y2 = (f ^ g) & e

	xor	y1, y0		# y0 = S1(e)
	xor	g, y2		# y2 = Ch(e, f, g) = ((f ^ g) & e) ^ g
	add	y2, h		# h = h + w + k + Ch(e, f, g)

	mov	b, y2		# y2 = b
	mov	b, T1		# T1 = b
	or	c, y2		# y2 = b | c
	and	c, T1		# T1 = b & c
	add	y0, h		# h = t1 = h + w + k + Ch(e, f, g) + S1(e)

	rorx	$39, a, y1	# y1 = a ror 39
	and	a, y2		# y2 = (b | c) & a
	rorx	$34, a, y0	# y0 = a ror 34
	or	T1, y2		# y2 = Maj(a, b, c) = ((b | c) & a) | (b & c)

	xor	y0, y1		# y1 = (a ror 39) ^ (a ror 34)
	rorx	$28, a, y0	# y0 = a ror 28
	add	h, d		# d = d + t1
	xor	y0, y1		# y1 = S0(a)

	add	y1, y2		# y2 = t2 = Maj(a, b, c) + S0(a)
	add	y2, h		# h = t1 + t2

	RotateState
.endm

# Compute 4 rounds (t-16..t-13) using W+K from frame_XFER while scheduling
# W[t..t+3] into Y_0 (then rotated to Y_3).  Vector comments show the low qword
# lane unless all lanes are written out as {q3, q2, q1, q0}.
.macro FOUR_ROUNDS_AND_SCHED
################################### Round t-16 ########################################

	# Compute W[t-16] + W[t-7] + s0(W[t-15]) for W[t..t+3]
	MY_VPALIGNR	YTMP0, Y_3, Y_2, 8		# YTMP0 = W[t-7]
	vpaddq		Y_0, YTMP0, YTMP0		# YTMP0 = W[t-16] + W[t-7]
	MY_VPALIGNR	YTMP1, Y_1, Y_0, 8		# YTMP1 = W[t-15]
	vpsrlq		$1, YTMP1, YTMP2		# YTMP2 = W[t-15] >> 1
	vpsllq		$(64-1), YTMP1, YTMP3		# YTMP3 = W[t-15] << 63
	vpor		YTMP2, YTMP3, YTMP3		# YTMP3 = W[t-15] ror 1
	vpsrlq		$7, YTMP1, YTMP4		# YTMP4 = W[t-15] >> 7

	SHA512_Round	0*8+frame_XFER(%rsp)

################################### Round t-15 ########################################

	vpshufb		YROR8, YTMP1, YTMP1		# YTMP1 = W[t-15] ror 8
	vpxor		YTMP4, YTMP3, YTMP3		# YTMP3 = (W[t-15] ror 1) ^ (W[t-15] >> 7)
	vpxor		YTMP1, YTMP3, YTMP1		# YTMP1 = s0(W[t-15])
	vpaddq		YTMP1, YTMP0, YTMP0		# YTMP0 = W[t-16] + W[t-7] + s0(W[t-15])

	# Compute s1({W[t-1], W[t-2]}) for {W[t+1], W[t]}
	vextracti128	$1, Y_3, XTMP2			# XTMP2 = {W[t-1], W[t-2]}
	vpsrlq		$6, XTMP2, XTMP4		# XTMP4 = W[t-2] >> 6

	SHA512_Round	1*8+frame_XFER(%rsp)

################################### Round t-14 ########################################

	vpsrlq		$19, XTMP2, XTMP3		# XTMP3 = W[t-2] >> 19
	vpsllq		$(64-19), XTMP2, XTMP1		# XTMP1 = W[t-2] << 45
	vpor		XTMP1, XTMP3, XTMP3		# XTMP3 = W[t-2] ror 19
	vpxor		XTMP3, XTMP4, XTMP4		# XTMP4 = (W[t-2] ror 19) ^ (W[t-2] >> 6)
	vpsrlq		$61, XTMP2, XTMP3		# XTMP3 = W[t-2] >> 61
	vpsllq		$(64-61), XTMP2, XTMP1		# XTMP1 = W[t-2] << 3
	vpor		XTMP1, XTMP3, XTMP3		# XTMP3 = W[t-2] ror 61
	vpxor		XTMP3, XTMP4, XTMP4		# YTMP4 = {0, 0, s1(W[t-1]), s1(W[t-2])}
	vpaddq		YTMP0, YTMP4, Y_0		# Y_0 = {YTMP0[3..2], W[t+1], W[t]}

	# Compute s1({W[t+1], W[t]}) for {W[t+3], W[t+2]}
	vpsrlq		$6, X_0, XTMP4			# XTMP4 = W[t] >> 6

	SHA512_Round	2*8+frame_XFER(%rsp)

################################### Round t-13 ########################################

	vpsrlq		$19, X_0, XTMP3			# XTMP3 = W[t] >> 19
	vpsllq		$(64-19), X_0, XTMP1		# XTMP1 = W[t] << 45
	vpor		XTMP1, XTMP3, XTMP3		# XTMP3 = W[t] ror 19
	vpxor		XTMP3, XTMP4, XTMP4		# XTMP4 = (W[t] ror 19) ^ (W[t] >> 6)
	vpsrlq		$61, X_0, XTMP3			# XTMP3 = W[t] >> 61
	vpsllq		$(64-61), X_0, XTMP1		# XTMP1 = W[t] << 3
	vpor		XTMP1, XTMP3, XTMP3		# XTMP3 = W[t] ror 61
	vpxor		XTMP3, XTMP4, XTMP4		# XTMP4 = {s1(W[t+1]), s1(W[t])}

	# Move s1 to bits 255:128 while zeroing bits 127:0, then add into Y_0
	vperm2i128	$0x08, YTMP4, YTMP4, YTMP4	# YTMP4 = {s1(W[t+1]), s1(W[t]), 0, 0}
	vpaddq		Y_0, YTMP4, Y_0			# Y_0 = {W[t+3], W[t+2], W[t+1], W[t]}

	SHA512_Round	3*8+frame_XFER(%rsp)

	rotate_Ys
.endm

.macro DO_4ROUNDS
	SHA512_Round	0*8+frame_XFER(%rsp)
	SHA512_Round	1*8+frame_XFER(%rsp)
	SHA512_Round	2*8+frame_XFER(%rsp)
	SHA512_Round	3*8+frame_XFER(%rsp)
.endm

########################################################################
# void sha512_transform_rorx(struct sha512_block_state *state,
#			     const u8 *data, size_t nblocks);
# Purpose: Updates the SHA512 digest stored at "state" with the message
# stored in "data".
# The size of the message pointed to by "data" must be an integer multiple
# of SHA512 message blocks.
# "nblocks" is the message length in SHA512 blocks.  Must be >= 1.
########################################################################
SYM_FUNC_START(sha512_transform_rorx)

	push	%rbp
	mov	%rsp, %rbp

	# Save GPRs
	push	%rbx
	push	%r12
	push	%r13
	push	%r14
	push	%r15

	# Allocate Stack Space
	sub	$frame_size, %rsp
	and	$~(0x20 - 1), %rsp

	shl	$7, NUM_BLKS	# convert to bytes
	add	INP, NUM_BLKS	# pointer to end of data
	mov	NUM_BLKS, frame_INPEND(%rsp)

	## load initial digest
	mov	8*0(CTX1), a
	mov	8*1(CTX1), b
	mov	8*2(CTX1), c
	mov	8*3(CTX1), d
	mov	8*4(CTX1), e
	mov	8*5(CTX1), f
	mov	8*6(CTX1), g
	mov	8*7(CTX1), h

	# save %rdi (CTX) before it gets clobbered
	mov	%rdi, frame_CTX(%rsp)

	vbroadcasti128	.L_XMM_QWORD_BSWAP(%rip), YBSWAP
	vbroadcasti128	.L_XMM_QWORD_ROR8(%rip), YROR8

.Lloop0:
	lea	K512(%rip), TBL

	# Load and byte-swap W[0..15]
.irp i, 0,1,2,3
	vmovdqu	\i*32(INP), Y_\i
	vpshufb	YBSWAP, Y_\i, Y_\i
.endr

	# Do rounds 0..63 and compute W[16..79] (interleaved) in four loop
	# iterations, each of which does four groups of four rounds.
	movq	$4, frame_SRND(%rsp)

.align 16
.Lloop1:
	vpaddq	(TBL), Y_0, XFER
	vmovdqa XFER, frame_XFER(%rsp)
	FOUR_ROUNDS_AND_SCHED

	vpaddq	1*32(TBL), Y_0, XFER
	vmovdqa XFER, frame_XFER(%rsp)
	FOUR_ROUNDS_AND_SCHED

	vpaddq	2*32(TBL), Y_0, XFER
	vmovdqa XFER, frame_XFER(%rsp)
	FOUR_ROUNDS_AND_SCHED

	vpaddq	3*32(TBL), Y_0, XFER
	vmovdqa XFER, frame_XFER(%rsp)
	add	$(4*32), TBL
	FOUR_ROUNDS_AND_SCHED

	subq	$1, frame_SRND(%rsp)
	jne	.Lloop1

	# Do rounds 64..79 in two loop iterations, each of which does two groups
	# of four rounds.
	movq	$2, frame_SRND(%rsp)
.Lloop2:
	vpaddq	(TBL), Y_0, XFER
	vmovdqa XFER, frame_XFER(%rsp)
	DO_4ROUNDS
	vpaddq	1*32(TBL), Y_1, XFER
	vmovdqa XFER, frame_XFER(%rsp)
	add	$(2*32), TBL
	DO_4ROUNDS

	vmovdqa	Y_2, Y_0
	vmovdqa	Y_3, Y_1

	subq	$1, frame_SRND(%rsp)
	jne	.Lloop2

	mov	frame_CTX(%rsp), CTX2
	addm	8*0(CTX2), a
	addm	8*1(CTX2), b
	addm	8*2(CTX2), c
	addm	8*3(CTX2), d
	addm	8*4(CTX2), e
	addm	8*5(CTX2), f
	addm	8*6(CTX2), g
	addm	8*7(CTX2), h

	add	$128, INP
	cmp	frame_INPEND(%rsp), INP
	jne	.Lloop0

	# Deallocate Stack Space
	lea	-40(%rbp), %rsp

	# Restore GPRs
	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	pop	%rbx
	pop	%rbp

	vzeroupper
	RET
SYM_FUNC_END(sha512_transform_rorx)

########################################################################
### Binary Data


# Mergeable 640-byte rodata section. This allows linker to merge the table
# with other, exactly the same 640-byte fragment of another rodata section
# (if such section exists).
.section	.rodata.cst640.K512, "aM", @progbits, 640
.align 64
# K[t] used in SHA512 hashing
K512:
	.quad	0x428a2f98d728ae22,0x7137449123ef65cd
	.quad	0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc
	.quad	0x3956c25bf348b538,0x59f111f1b605d019
	.quad	0x923f82a4af194f9b,0xab1c5ed5da6d8118
	.quad	0xd807aa98a3030242,0x12835b0145706fbe
	.quad	0x243185be4ee4b28c,0x550c7dc3d5ffb4e2
	.quad	0x72be5d74f27b896f,0x80deb1fe3b1696b1
	.quad	0x9bdc06a725c71235,0xc19bf174cf692694
	.quad	0xe49b69c19ef14ad2,0xefbe4786384f25e3
	.quad	0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65
	.quad	0x2de92c6f592b0275,0x4a7484aa6ea6e483
	.quad	0x5cb0a9dcbd41fbd4,0x76f988da831153b5
	.quad	0x983e5152ee66dfab,0xa831c66d2db43210
	.quad	0xb00327c898fb213f,0xbf597fc7beef0ee4
	.quad	0xc6e00bf33da88fc2,0xd5a79147930aa725
	.quad	0x06ca6351e003826f,0x142929670a0e6e70
	.quad	0x27b70a8546d22ffc,0x2e1b21385c26c926
	.quad	0x4d2c6dfc5ac42aed,0x53380d139d95b3df
	.quad	0x650a73548baf63de,0x766a0abb3c77b2a8
	.quad	0x81c2c92e47edaee6,0x92722c851482353b
	.quad	0xa2bfe8a14cf10364,0xa81a664bbc423001
	.quad	0xc24b8b70d0f89791,0xc76c51a30654be30
	.quad	0xd192e819d6ef5218,0xd69906245565a910
	.quad	0xf40e35855771202a,0x106aa07032bbd1b8
	.quad	0x19a4c116b8d2d0c8,0x1e376c085141ab53
	.quad	0x2748774cdf8eeb99,0x34b0bcb5e19b48a8
	.quad	0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb
	.quad	0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3
	.quad	0x748f82ee5defb2fc,0x78a5636f43172f60
	.quad	0x84c87814a1f0ab72,0x8cc702081a6439ec
	.quad	0x90befffa23631e28,0xa4506cebde82bde9
	.quad	0xbef9a3f7b2c67915,0xc67178f2e372532b
	.quad	0xca273eceea26619c,0xd186b8c721c0c207
	.quad	0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178
	.quad	0x06f067aa72176fba,0x0a637dc5a2c898a6
	.quad	0x113f9804bef90dae,0x1b710b35131c471b
	.quad	0x28db77f523047d84,0x32caab7b40c72493
	.quad	0x3c9ebe0a15c9bebc,0x431d67c49c100d4c
	.quad	0x4cc5d4becb3e42b6,0x597f299cfc657e2a
	.quad	0x5fcb6fab3ad6faec,0x6c44198c4a475817

.section	.rodata.cst16.XMM_QWORD_BSWAP, "aM", @progbits, 16
.align 16
# Mask for byte-swapping each qword using vpshufb
.L_XMM_QWORD_BSWAP:
	.octa 0x08090a0b0c0d0e0f0001020304050607

.section	.rodata.cst16.XMM_QWORD_ROR8, "aM", @progbits, 16
.align 16
# Mask for rotating each qword right by 8 bits using vpshufb
.L_XMM_QWORD_ROR8:
	.octa 0x080f0e0d0c0b0a090007060504030201
