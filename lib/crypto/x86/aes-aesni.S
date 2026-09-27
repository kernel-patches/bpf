/* SPDX-License-Identifier: GPL-2.0-or-later */
//
// AES block cipher using AES-NI instructions
//
// Copyright 2026 Google LLC
//
// The code in this file supports 32-bit and 64-bit CPUs, and it doesn't require
// AVX.  It does use up to SSE4.1, which all CPUs with AES-NI have.
#include <linux/linkage.h>

#ifdef __x86_64__
#define RODATA(label)	label(%rip)

#define ARG0		%rdi
#define ARG1		%rsi
#define ARG2		%rdx
#define ARG2_32		%edx
#define ARG3		%rcx
#define ARG4		%r8
#define TMP		%rax
#define TMP_32		%eax
#define TMP_16		%ax
#define TMP_8		%al

#else // __x86_64__

#define RODATA(label)	label

// Caller-save GPRs and the first 3 function arguments, assuming -mregparm=3
#define ARG0		%eax
#define ARG1		%edx
#define ARG2		%ecx
#define ARG2_32		%ecx

// *Callee*-save GPRs.
#define ARG3		%edi
#define ARG4		%esi
#define TMP		%ebx
#define TMP_32		%ebx
#define TMP_16		%bx
#define TMP_8		%bl
#endif // !__x86_64__

// Offsets in struct aes_key
#define OFFSETOF_NROUNDS	4
#define OFFSETOF_ROUNDKEYS	16
#define OFFSETOF_INVROUNDKEYS	256

.section .rodata
.p2align 4
.Lexpandkey_mask:
	// A mask for pshufb that extracts the last dword, rotates it right by 8
	// bits, and copies the result to all four dwords.
	.byte	13, 14, 15, 12, 13, 14, 15, 12, 13, 14, 15, 12, 13, 14, 15, 12

.Lrcon:
	// The AES round constants, used during key expansion
	.long	0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36

.text

// In 32-bit mode, push certain callee-saved GPRs and optionally load function
// arguments from the stack into them.  Do nothing in 64-bit mode.
//
// TMP is always made available as a temporary register.
//
// \uses_arg3 is 0 to not touch ARG3, 1 to make it available as a temporary
// register only, or 2 to actually load it as an argument from the stack.
// Likewise for \uses_arg4 and ARG4.  It's assumed the -mregparm=3 convention is
// being used and %esp hasn't been modified since function entry.
.macro _prologue	uses_arg3=0, uses_arg4=0
#ifdef __i386__
	.set	ARG3_OFFSET, 4	// Assuming -mregparm=3
	.set	ARG3_PUSHED, \uses_arg3
	.set	ARG4_PUSHED, \uses_arg4
.if \uses_arg3
	push	ARG3
	.set	ARG3_OFFSET, ARG3_OFFSET + 4
  .if \uses_arg3 == 2
	mov	ARG3_OFFSET(%esp), ARG3
  .endif
.endif
.if \uses_arg4
	push	ARG4
	.set	ARG3_OFFSET, ARG3_OFFSET + 4
  .if \uses_arg4 == 2
	mov	ARG3_OFFSET+4(%esp), ARG4
  .endif
.endif
	push	TMP
	.set	ARG3_OFFSET, ARG3_OFFSET + 4
#endif // __i386__
.endm

.macro _reload_arg3
#ifdef __i386__
	mov	ARG3_OFFSET(%esp), ARG3
#endif
.endm

// Undo any pushes that _prologue did, then return.
.macro _epilogue
#ifdef __i386__
	pop	TMP
.if ARG4_PUSHED
	pop	ARG4
.endif
.if ARG3_PUSHED
	pop	ARG3
.endif
#endif
	RET
.endm

.macro	_aesenc		enc, rndkey, data
.if \enc
	aesenc		\rndkey, \data
.else
	aesdec		\rndkey, \data
.endif
.endm

.macro	_aesenclast	enc, rndkeylast, data
.if \enc
	aesenclast	\rndkeylast, \data
.else
	aesdeclast	\rndkeylast, \data
.endif
.endm

// Transform four dwords [a0, a1, a2, a3] in \a into
// [a0, a0^a1, a0^a1^a2, a0^a1^a2^a3].  \tmp is a temporary xmm register.
//
// Note: this could be done in four instructions, shufps + pxor + shufps + pxor,
// if the temporary register were zero-initialized ahead of time.  We instead do
// it in an easier-to-understand way that doesn't require zero-initialization
// and avoids the unusual shufps instruction.  movdqa is usually "free" anyway.
.macro	_prefix_sum	a, tmp
	movdqa		\a, \tmp	// [a0, a1, a2, a3]
	pslldq		$4, \a		// [0, a0, a1, a2]
	pxor		\tmp, \a	// [a0, a0^a1, a1^a2, a2^a3]
	movdqa		\a, \tmp
	pslldq		$8, \a		// [0, 0, a0, a0^a1]
	pxor		\tmp, \a	// [a0, a0^a1, a0^a1^a2, a0^a1^a2^a3]
.endm

.macro	_gen_round_key	a, b
	// Compute four copies of rcon[i] ^ SubBytes(ror32(w, 8)), where w is
	// the last dword of the previous round key (given in \b).
	//
	// 'aesenclast src, dst' does dst = src XOR SubBytes(ShiftRows(dst)).
	// It is used here solely for the SubBytes and the XOR.  The ShiftRows
	// is a no-op because all four columns are the same here.
	//
	// Don't use the 'aeskeygenassist' instruction, since:
	//  - On most Intel CPUs it is microcoded, making it have a much higher
	//    latency and use more execution ports than 'aesenclast'.
	//  - It cannot be used in a loop, since it requires an immediate.
	//  - It doesn't do much more than 'aesenclast' in the first place.
	movdqa		\b, %xmm2
	pshufb		MASK, %xmm2
	aesenclast	RCON, %xmm2

	// XOR in the prefix sum of the four dwords of \a, which is the
	// previous round key (AES-128) or the first round key in the previous
	// pair of round keys (AES-256).  The result is the next round key.
	_prefix_sum	\a, tmp=%xmm3
	pxor		%xmm2, \a

	// Store the next round key to memory.  Also leave it in \a.
	movdqu		\a, (RNDKEYS)
.endm

.macro	_aes_expandkey_aesni	is_aes128
	// Arguments
	.set	RNDKEYS,	ARG0
	.set	INV_RNDKEYS,	ARG1
	.set	IN_KEY,		ARG2

	// Other local variables
	.set	RCON_PTR,	ARG3
	.set	COUNTER,	TMP_32
	.set	RCON,		%xmm6
	.set	MASK,		%xmm7

	_prologue	uses_arg3=1

.if \is_aes128
	// AES-128: the first round key is simply a copy of the raw key.
	movdqu		(IN_KEY), %xmm0
	movdqu		%xmm0, (RNDKEYS)
.else
	// AES-256: the first two round keys are simply a copy of the raw key.
	movdqu		(IN_KEY), %xmm0
	movdqu		%xmm0, (RNDKEYS)
	movdqu		16(IN_KEY), %xmm1
	movdqu		%xmm1, 16(RNDKEYS)
	add		$32, RNDKEYS
.endif

	// Generate the remaining round keys.
	movdqa		RODATA(.Lexpandkey_mask), MASK
.if \is_aes128
	lea		RODATA(.Lrcon), RCON_PTR
	mov		$10, COUNTER
.Lgen_next_aes128_round_key:
	add		$16, RNDKEYS
	movd		(RCON_PTR), RCON
	pshufd		$0x00, RCON, RCON
	add		$4, RCON_PTR
	_gen_round_key	%xmm0, %xmm0
	dec		COUNTER
	jnz		.Lgen_next_aes128_round_key
.else
	// AES-256: only the first 7 round constants are needed, so instead of
	// loading each one from memory, just start by loading [1, 1, 1, 1] and
	// then generate the rest by doubling.
	pshufd		$0x00, RODATA(.Lrcon), RCON
	pxor		%xmm5, %xmm5	// All-zeroes
	mov		$7, COUNTER
.Lgen_next_aes256_round_key_pair:
	// Generate the next AES-256 round key: either the first of a pair of
	// two, or the last one.
	_gen_round_key	%xmm0, %xmm1

	dec		COUNTER
	jz		.Lgen_aes256_round_keys_done

	// Generate the second AES-256 round key of the pair.  Compared to the
	// first, there's no rotation and no XOR of a round constant.
	pshufd		$0xff, %xmm0, %xmm2	// Get four copies of last dword
	aesenclast	%xmm5, %xmm2		// Just does SubBytes
	_prefix_sum	%xmm1, tmp=%xmm3
	pxor		%xmm2, %xmm1
	movdqu		%xmm1, 16(RNDKEYS)
	add		$32, RNDKEYS
	paddd		RCON, RCON		// RCON <<= 1
	jmp		.Lgen_next_aes256_round_key_pair
.Lgen_aes256_round_keys_done:
.endif

	// If INV_RNDKEYS is non-NULL, write the round keys for the Equivalent
	// Inverse Cipher to it.  To do that, reverse the standard round keys,
	// and apply aesimc (InvMixColumn) to each except the first and last.
	test		INV_RNDKEYS, INV_RNDKEYS
	jz		.Ldone\@
	movdqu		(RNDKEYS), %xmm0	// Last standard round key
	movdqu		%xmm0, (INV_RNDKEYS)	// => First inverse round key
.if \is_aes128
	mov		$9, COUNTER
.else
	mov		$13, COUNTER
.endif
.Lgen_next_inv_round_key\@:
	sub		$16, RNDKEYS
	add		$16, INV_RNDKEYS
	movdqu		(RNDKEYS), %xmm0
	aesimc		%xmm0, %xmm0
	movdqu		%xmm0, (INV_RNDKEYS)
	dec		COUNTER
	jnz		.Lgen_next_inv_round_key\@
	movdqu		-16(RNDKEYS), %xmm0	// First standard round key
	movdqu		%xmm0, 16(INV_RNDKEYS)	// => Last inverse round key

.Ldone\@:
	_epilogue
.endm

// void aes128_expandkey_aesni(u32 rndkeys[], u32 *inv_rndkeys,
//			       const u8 in_key[AES_KEYSIZE_128]);
SYM_FUNC_START(aes128_expandkey_aesni)
	_aes_expandkey_aesni	1
SYM_FUNC_END(aes128_expandkey_aesni)

// void aes256_expandkey_aesni(u32 rndkeys[], u32 *inv_rndkeys,
//			       const u8 in_key[AES_KEYSIZE_256]);
SYM_FUNC_START(aes256_expandkey_aesni)
	_aes_expandkey_aesni	0
SYM_FUNC_END(aes256_expandkey_aesni)

// AES-encrypt (\enc=1) or AES-decrypt (\enc=0) the AESDATA registers specified
// in \vecs using the aes_enckey or aes_key pointed to by KEY.  RNDKEY must be
// set to a temporary XMM register, NROUNDS to a temporary 32-bit GPR, and
// RNDKEY_PTR to a temporary full-size GPR.
.macro	_do_aes		enc, vecs:vararg
	movl		OFFSETOF_NROUNDS(KEY), NROUNDS
	dec		NROUNDS
.if \enc
	.set		rndkey0_offs, OFFSETOF_ROUNDKEYS
.else
	.set		rndkey0_offs, OFFSETOF_INVROUNDKEYS
.endif

	// Do the zero-th AES round.
	movdqu		rndkey0_offs(KEY), RNDKEY
.irp i, \vecs
	pxor		RNDKEY, AESDATA\i
.endr
	// Do the regular AES rounds.
	lea		rndkey0_offs+16(KEY), RNDKEY_PTR
.Lnext_round\@:
	movdqu		(RNDKEY_PTR), RNDKEY
	add		$16, RNDKEY_PTR
.irp i, \vecs
	_aesenc		\enc, RNDKEY, AESDATA\i
.endr
	dec		NROUNDS
	jnz		.Lnext_round\@
	// Do the last AES round.
	movdqu		(RNDKEY_PTR), RNDKEY
.irp i, \vecs
	_aesenclast	\enc, RNDKEY, AESDATA\i
.endr
.endm

.macro	_do_aes_ecb	enc, vecs:vararg
.irp i, \vecs
	movdqu		\i*16(SRC), AESDATA\i
.endr
	_do_aes		\enc, \vecs
.irp i, \vecs
	movdqu		AESDATA\i, \i*16(DST)
.endr
.endm

.macro	_aes_crypt_aesni	enc
	.set	DST,		ARG0
	.set	SRC,		ARG1
	.set	KEY,		ARG2
	.set	RNDKEY_PTR,	ARG3	// Temporary register for _do_aes
	.set	NROUNDS,	TMP_32	// Temporary register for _do_aes
	.set	AESDATA0,	%xmm0
	.set	RNDKEY,		%xmm1	// Temporary register for _do_aes

	_prologue	uses_arg3=1
	_do_aes_ecb	\enc, 0
	_epilogue
.endm

// void aes_encrypt_aesni(u8 dst[AES_BLOCK_SIZE], const u8 src[AES_BLOCK_SIZE],
//			  const struct aes_enckey *key);
SYM_FUNC_START(aes_encrypt_aesni)
	_aes_crypt_aesni	1
SYM_FUNC_END(aes_encrypt_aesni)

// void aes_decrypt_aesni(u8 dst[AES_BLOCK_SIZE], const u8 src[AES_BLOCK_SIZE],
//			  const struct aes_key *key);
SYM_FUNC_START(aes_decrypt_aesni)
	_aes_crypt_aesni	0
SYM_FUNC_END(aes_decrypt_aesni)

.macro	_ecb_crypt	enc
	// Arguments
	.set	DST,		ARG0
	.set	SRC,		ARG1
	.set	NBLOCKS,	ARG2
	.set	NBLOCKS32,	ARG2_32	// Used for improved code density
	.set	KEY,		ARG3

	// Other local variables
	.set	RNDKEY_PTR,	ARG4	// Temporary register for _do_aes
	.set	NROUNDS,	TMP_32	// Temporary register for _do_aes
	.set	AESDATA0,	%xmm0
	.set	AESDATA1,	%xmm1
	.set	AESDATA2,	%xmm2
	.set	AESDATA3,	%xmm3
	.set	RNDKEY,		%xmm4	// Temporary register for _do_aes
	_prologue	uses_arg3=2, uses_arg4=1

	sub		$4, NBLOCKS
	jl		.Lecb_loop4_done\@
.p2align 5
.Lecb_loop4\@:
	_do_aes_ecb	\enc, 0,1,2,3
	add		$64, SRC
	add		$64, DST
	sub		$4, NBLOCKS
	jge		.Lecb_loop4\@
.Lecb_loop4_done\@:
	add		$4, NBLOCKS32
	jz		.Lecb_done\@

.Lecb_loop1\@:
	_do_aes_ecb	\enc, 0
	add		$16, SRC
	add		$16, DST
	dec		NBLOCKS32
	jnz		.Lecb_loop1\@

.Lecb_done\@:
	_epilogue
.endm

// void aes_ecb_encrypt_aesni(u8 *dst, const u8 *src, long nblocks,
//			      const struct aes_enckey *key);
SYM_FUNC_START(aes_ecb_encrypt_aesni)
	_ecb_crypt	1
SYM_FUNC_END(aes_ecb_encrypt_aesni)

// void aes_ecb_decrypt_aesni(u8 *dst, const u8 *src, long nblocks,
//			      const struct aes_key *key);
SYM_FUNC_START(aes_ecb_decrypt_aesni)
	_ecb_crypt	0
SYM_FUNC_END(aes_ecb_decrypt_aesni)
