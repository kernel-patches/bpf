// SPDX-License-Identifier: GPL-2.0
/*
 * The arena accesses of jit_insns in their own object, so that a kernel
 * without arena support fails only these programs.
 */
#define BPF_NO_KFUNC_PROTOTYPES
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"
#include "bpf_arena_common.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 2);
} arena SEC(".maps");

/*
 * The first bytes in memory of the test value and its sum with the slot
 * after the u32 store depend on the byte order.
 */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define VAL_B0	0x88
#define VAL_H0	0x7788
#define VAL_W0	0x55667788
#define VAL_SUM	0x22446688556689bc
#else
#define VAL_B0	0x11
#define VAL_H0	0x1122
#define VAL_W0	0x11223344
#define VAL_SUM	0x11224578aaccef10
#endif

/*
 * The load-acquire and store-release, which clang has syntax for only with
 * __BPF_FEATURE_LOAD_ACQ_STORE_REL, as the 64-bit word of their fields for
 * .8byte, in the byte order of the target: the two register nibbles share a
 * byte, which the first bitfield of struct bpf_insn takes from the low end
 * on little endian and from the high end on big endian.
 */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define INSN(CODE, DST, SRC, OFF, IMM)						\
	((__u64)(__u8)(CODE) | ((__u64)(DST) << 8) | ((__u64)(SRC) << 12) |	\
	 ((__u64)(__u16)(OFF) << 16) | ((__u64)(__u32)(IMM) << 32))
#else
#define INSN(CODE, DST, SRC, OFF, IMM)						\
	(((__u64)(__u8)(CODE) << 56) | ((__u64)(DST) << 52) | ((__u64)(SRC) << 48) | \
	 ((__u64)(__u16)(OFF) << 32) | (__u64)(__u32)(IMM))
#endif
#define ATOMIC(SIZE, OP, DST, SRC, OFF)	INSN(BPF_STX | BPF_ATOMIC | (SIZE), DST, SRC, OFF, OP)

/* The fields of those instructions, which vmlinux.h does not carry */
#ifndef BPF_STX
#define BPF_STX		0x03
#define BPF_W		0x00
#define BPF_B		0x10
#define BPF_DW		0x18
#define BPF_ATOMIC	0xc0
#endif
#ifndef BPF_LOAD_ACQ
#define BPF_LOAD_ACQ	0x100
#define BPF_STORE_REL	0x110
#endif

/*
 * The JITs that take the sign extending loads, the atomics, and the
 * load-acquire and store-release in the arena, the last as arena_atomics.c
 * lists them. The atomics other than loads and stores need LSE on arm64,
 * and cmpxchg needs Zacas on riscv64.
 */
#if defined(__TARGET_ARCH_arm64) || defined(__TARGET_ARCH_x86) ||		\
	(defined(__TARGET_ARCH_riscv) && __riscv_xlen == 64)
#define ARENA_LDSX
#endif
#if defined(__TARGET_ARCH_arm64) || defined(__TARGET_ARCH_x86) ||		\
	(defined(__TARGET_ARCH_riscv) && __riscv_xlen == 64) ||			\
	defined(__TARGET_ARCH_s390) || defined(__TARGET_ARCH_powerpc)
#define ARENA_ATOMICS
#endif
#if defined(__TARGET_ARCH_arm64) || defined(__TARGET_ARCH_x86) ||		\
	(defined(__TARGET_ARCH_riscv) && __riscv_xlen == 64) ||			\
	defined(__TARGET_ARCH_s390)
#define ARENA_ACQ_REL
#endif

/* The first byte in memory of the u32 0x12abcdef depends on the byte order */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define ACQ_B0	0xef
#else
#define ACQ_B0	0x12
#endif

#if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
SEC("syscall")
__success __retval(0)
int arena_zero_off(void *ctx)
{
	void __arena *page;
	__u64 res;

	page = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
	if (!page)
		return 1;
	res = (__u32)(__u64)page;
	/* Accesses through two base registers */
	asm volatile ("					\
	r7 = %[res];					\
	r7 = addr_space_cast(r7, 0x0, 0x1);		\
	r1 = r7;					\
	r8 = 0x1122334455667788 ll;			\
	*(u64 *)(r7 + 0) = r8;				\
	r9 = *(u64 *)(r7 + 0);				\
	r9 ^= r8;					\
	*(u64 *)(r1 + 0) = r8;				\
	r2 = *(u64 *)(r1 + 0);				\
	r2 ^= r8;					\
	r9 |= r2;					\
	r3 = *(u8 *)(r1 + 0);				\
	r3 ^= %[b0];					\
	r9 |= r3;					\
	r4 = *(u16 *)(r1 + 0);				\
	r4 ^= %[h0];					\
	r9 |= r4;					\
	r5 = *(u32 *)(r1 + 0);				\
	r5 ^= %[w0];					\
	r9 |= r5;					\
	*(u32 *)(r1 + 0) = 0x1234;			\
	lock *(u64 *)(r7 + 0) += r8;			\
	r2 = *(u64 *)(r1 + 0);				\
	r8 = %[sum] ll;					\
	r2 ^= r8;					\
	r9 |= r2;					\
	%[res] = r9;					\
"	: [res]"+r"(res)
	: __imm_const(b0, VAL_B0), __imm_const(h0, VAL_H0),
	  __imm_const(w0, VAL_W0), __imm_const(sum, VAL_SUM)
	: "r1", "r2", "r3", "r4", "r5", "r7", "r8", "r9");
	return res != 0;
}

SEC("syscall")
__success __retval(0)
int cast_to_user(void *ctx)
{
	void __arena *page;
	__u64 res;

	page = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
	if (!page)
		return 1;
	/* The user address comes back from the kernel one, NULL stays NULL */
	asm volatile ("					\
	r7 = %[page];					\
	r1 = addr_space_cast(r7, 0x0, 0x1);		\
	r1 = addr_space_cast(r1, 0x1, 0x0);		\
	r9 = r1;					\
	r9 ^= r7;					\
	r2 = 0;						\
	r2 = addr_space_cast(r2, 0x1, 0x0);		\
	r9 |= r2;					\
	%[res] = r9;					\
"	: [res]"=r"(res)
	: [page]"r"(page)
	: "r1", "r2", "r7", "r9");
	return res != 0;
}

/*
 * Every form of the address computation of an arena access: an immediate
 * offset the add takes, one the sub takes into the page before, one the
 * shifted add takes, one that needs a move, the end of the second page,
 * the narrower sizes, and the immediate stores of a zero and of another
 * value. Each access is checked through r2, the same address computed into
 * a register: a store is read back through it, and a load gets a value
 * written through it, with the slot cleared again, so that a load and a
 * store at the same wrong address, or one at the slot of another, fail.
 */
SEC("syscall")
__success __retval(0)
__naked void arena_offsets(void)
{
	asm volatile ("					\
	r1 = %[arena] ll;				\
	r2 = 0;						\
	r3 = 2;						\
	r4 = -1;					\
	r5 = 0;						\
	call bpf_arena_alloc_pages;			\
	r7 = r0;					\
	r0 = 1;						\
	if r7 == 0 goto 9f;				\
	r7 = addr_space_cast(r7, 0x0, 0x1);		\
	r6 = r7;					\
	r6 += 0x1000;					\
	r9 = 0;						\
	r8 = 0x1122334455667788 ll;			\
	r5 = 0x0123456789abcdef ll;			\
	r2 = r7;					\
	r2 += 8;					\
	*(u64 *)(r7 + 8) = r8;				\
	r1 = *(u64 *)(r2 + 0);				\
	r1 ^= r8;					\
	r9 |= r1;					\
	*(u64 *)(r2 + 0) = r5;				\
	r1 = *(u64 *)(r7 + 8);				\
	r1 ^= r5;					\
	r9 |= r1;					\
	*(u64 *)(r2 + 0) = 0;				\
	r2 = r7;					\
	r2 += 0xff8;					\
	*(u64 *)(r6 - 8) = r8;				\
	r1 = *(u64 *)(r2 + 0);				\
	r1 ^= r8;					\
	r9 |= r1;					\
	*(u64 *)(r2 + 0) = r5;				\
	r1 = *(u64 *)(r6 - 8);				\
	r1 ^= r5;					\
	r9 |= r1;					\
	*(u64 *)(r2 + 0) = 0;				\
	r2 = r7;					\
	r2 += 0x1000;					\
	*(u64 *)(r7 + 0x1000) = r8;			\
	r1 = *(u64 *)(r2 + 0);				\
	r1 ^= r8;					\
	r9 |= r1;					\
	*(u64 *)(r2 + 0) = r5;				\
	r1 = *(u64 *)(r7 + 0x1000);			\
	r1 ^= r5;					\
	r9 |= r1;					\
	*(u64 *)(r2 + 0) = 0;				\
	r2 = r7;					\
	r2 += 0x1238;					\
	*(u64 *)(r7 + 0x1238) = r8;			\
	r1 = *(u64 *)(r2 + 0);				\
	r1 ^= r8;					\
	r9 |= r1;					\
	*(u64 *)(r2 + 0) = r5;				\
	r1 = *(u64 *)(r7 + 0x1238);			\
	r1 ^= r5;					\
	r9 |= r1;					\
	*(u64 *)(r2 + 0) = 0;				\
	r2 = r7;					\
	r2 += 0x1ff8;					\
	*(u64 *)(r7 + 0x1ff8) = r8;			\
	r1 = *(u64 *)(r2 + 0);				\
	r1 ^= r8;					\
	r9 |= r1;					\
	*(u64 *)(r2 + 0) = r5;				\
	r1 = *(u64 *)(r7 + 0x1ff8);			\
	r1 ^= r5;					\
	r9 |= r1;					\
	*(u64 *)(r2 + 0) = 0;				\
	r2 = r7;					\
	r2 += 20;					\
	*(u32 *)(r7 + 20) = r8;				\
	r1 = *(u32 *)(r2 + 0);				\
	w1 ^= w8;					\
	r9 |= r1;					\
	*(u32 *)(r2 + 0) = r5;				\
	r1 = *(u32 *)(r7 + 20);				\
	w1 ^= w5;					\
	r9 |= r1;					\
	*(u32 *)(r2 + 0) = 0;				\
	r2 = r7;					\
	r2 += 26;					\
	*(u16 *)(r7 + 26) = r8;				\
	r1 = *(u16 *)(r2 + 0);				\
	r1 ^= 0x7788;					\
	r9 |= r1;					\
	*(u16 *)(r2 + 0) = r5;				\
	r1 = *(u16 *)(r7 + 26);				\
	r1 ^= 0xcdef;					\
	r9 |= r1;					\
	*(u16 *)(r2 + 0) = 0;				\
	r2 = r7;					\
	r2 += 29;					\
	*(u8 *)(r7 + 29) = r8;				\
	r1 = *(u8 *)(r2 + 0);				\
	r1 ^= 0x88;					\
	r9 |= r1;					\
	*(u8 *)(r2 + 0) = r5;				\
	r1 = *(u8 *)(r7 + 29);				\
	r1 ^= 0xef;					\
	r9 |= r1;					\
	*(u8 *)(r2 + 0) = 0;				\
	r2 = r7;					\
	r2 += 8;					\
	*(u64 *)(r2 + 0) = r5;				\
	*(u64 *)(r7 + 8) = 0;				\
	r1 = *(u64 *)(r2 + 0);				\
	r9 |= r1;					\
	*(u64 *)(r7 + 8) = 0x12345;			\
	r1 = *(u64 *)(r2 + 0);				\
	r1 ^= 0x12345;					\
	r9 |= r1;					\
	*(u32 *)(r7 + 8) = -1;				\
	r1 = *(u32 *)(r2 + 0);				\
	w1 ^= -1;					\
	r9 |= r1;					\
	r0 = 0;						\
	if r9 == 0 goto 9f;				\
	r0 = 1;						\
9:	exit;						\
"	:
	: __imm_addr(arena)
	: __clobber_all);
}

/*
 * The sign extending loads at an offset, of a value per size written
 * through r2, the address computed into a register.
 */
#ifdef ARENA_LDSX
SEC("syscall")
__success __retval(0)
__naked void arena_offsets_ldsx(void)
{
	asm volatile ("					\
	r1 = %[arena] ll;				\
	r2 = 0;						\
	r3 = 2;						\
	r4 = -1;					\
	r5 = 0;						\
	call bpf_arena_alloc_pages;			\
	r7 = r0;					\
	r0 = 1;						\
	if r7 == 0 goto 9f;				\
	r7 = addr_space_cast(r7, 0x0, 0x1);		\
	r9 = 0;						\
	r2 = r7;					\
	r2 += 40;					\
	*(u8 *)(r2 + 0) = -16;				\
	r2 = r7;					\
	r2 += 42;					\
	*(u16 *)(r2 + 0) = -0x1234;			\
	r2 = r7;					\
	r2 += 44;					\
	*(u32 *)(r2 + 0) = -0x12345678;			\
	r1 = *(s8 *)(r7 + 40);				\
	r1 += 16;					\
	r9 |= r1;					\
	r1 = *(s16 *)(r7 + 42);				\
	r1 += 0x1234;					\
	r9 |= r1;					\
	r1 = *(s32 *)(r7 + 44);				\
	r1 += 0x12345678;				\
	r9 |= r1;					\
	r0 = 0;						\
	if r9 == 0 goto 9f;				\
	r0 = 1;						\
9:	exit;						\
"	:
	: __imm_addr(arena)
	: __clobber_all);
}
#endif /* ARENA_LDSX */

/*
 * The atomics at an offset and at zero, the result at the offset read
 * through r6, the address computed into a register.
 */
#ifdef ARENA_ATOMICS
SEC("syscall")
__success __retval(0)
__naked void arena_offsets_atomics(void)
{
	asm volatile ("					\
	r1 = %[arena] ll;				\
	r2 = 0;						\
	r3 = 2;						\
	r4 = -1;					\
	r5 = 0;						\
	call bpf_arena_alloc_pages;			\
	r7 = r0;					\
	r0 = 1;						\
	if r7 == 0 goto 9f;				\
	r7 = addr_space_cast(r7, 0x0, 0x1);		\
	r6 = r7;					\
	r6 += 0x1008;					\
	r9 = 0;						\
	r1 = 0x10;					\
	*(u64 *)(r7 + 0x1008) = r1;			\
	r8 = 1;						\
	lock *(u64 *)(r7 + 0x1008) += r8;		\
	r2 = 1;						\
	r2 = atomic_fetch_add((u64 *)(r7 + 0x1008), r2);	\
	r2 ^= 0x11;					\
	r9 |= r2;					\
	r3 = 0x77;					\
	r3 = xchg_64(r7 + 0x1008, r3);			\
	r3 ^= 0x12;					\
	r9 |= r3;					\
	r0 = 0x77;					\
	r4 = 0x99;					\
	r0 = cmpxchg_64(r7 + 0x1008, r0, r4);		\
	r0 ^= 0x77;					\
	r9 |= r0;					\
	r1 = *(u64 *)(r6 + 0);				\
	r1 ^= 0x99;					\
	r9 |= r1;					\
	w1 = 0x10;					\
	*(u32 *)(r7 + 0) = w1;				\
	w8 = 1;						\
	lock *(u32 *)(r7 + 0) += w8;			\
	w2 = 1;						\
	w2 = atomic_fetch_add((u32 *)(r7 + 0), w2);	\
	w2 ^= 0x11;					\
	r9 |= r2;					\
	w3 = 0x77;					\
	w3 = xchg32_32(r7 + 0, w3);			\
	w3 ^= 0x12;					\
	r9 |= r3;					\
	w0 = 0x77;					\
	w4 = 0x99;					\
	w0 = cmpxchg32_32(r7 + 0, w0, w4);		\
	w0 ^= 0x77;					\
	r9 |= r0;					\
	r1 = *(u32 *)(r7 + 0);				\
	w1 ^= 0x99;					\
	r9 |= r1;					\
	r0 = 0;						\
	if r9 == 0 goto 9f;				\
	r0 = 1;						\
9:	exit;						\
"	:
	: __imm_addr(arena)
	: __clobber_all);
}
#endif /* ARENA_ATOMICS */

#ifdef ARENA_ACQ_REL
/*
 * The load-acquire and the store-release at an offset and at zero, the
 * ones at the offset checked through r3, the address computed into a
 * register, with a plain load and store.
 */
SEC("syscall")
__success __retval(0)
__naked void arena_acq_rel(void)
{
	asm volatile ("					\
	r1 = %[arena] ll;				\
	r2 = 0;						\
	r3 = 1;						\
	r4 = -1;					\
	r5 = 0;						\
	call bpf_arena_alloc_pages;			\
	r7 = r0;					\
	r0 = 1;						\
	if r7 == 0 goto 9f;				\
	r7 = addr_space_cast(r7, 0x0, 0x1);		\
	r3 = r7;					\
	r3 += 8;					\
	r9 = 0;						\
	r1 = 0x1234;					\
	.8byte %[store_rel8];	/* store_release((u64 *)(r7 + 8), r1) */	\
	r2 = *(u64 *)(r3 + 0);				\
	r2 ^= 0x1234;					\
	r9 |= r2;					\
	r1 = 0x5678;					\
	*(u64 *)(r3 + 0) = r1;				\
	.8byte %[load_acq8];	/* r2 = load_acquire((u64 *)(r7 + 8)) */	\
	r2 ^= 0x5678;					\
	r9 |= r2;					\
	w1 = 0x12abcdef;				\
	.8byte %[store_rel0];	/* store_release((u32 *)(r7 + 0), w1) */	\
	.8byte %[load_acq0];	/* w2 = load_acquire((u8 *)(r7 + 0)) */	\
	r2 ^= %[b0];					\
	r9 |= r2;					\
	r1 = *(u32 *)(r7 + 0);				\
	w1 ^= 0x12abcdef;				\
	r9 |= r1;					\
	r0 = 0;						\
	if r9 == 0 goto 9f;				\
	r0 = 1;						\
9:	exit;						\
"	:
	: __imm_addr(arena),
	  __imm_const(b0, ACQ_B0),
	  __imm_const(store_rel8, ATOMIC(BPF_DW, BPF_STORE_REL, 7, 1, 8)),
	  __imm_const(load_acq8, ATOMIC(BPF_DW, BPF_LOAD_ACQ, 2, 7, 8)),
	  __imm_const(store_rel0, ATOMIC(BPF_W, BPF_STORE_REL, 7, 1, 0)),
	  __imm_const(load_acq0, ATOMIC(BPF_B, BPF_LOAD_ACQ, 2, 7, 0))
	: __clobber_all);
}
#endif /* ARENA_ACQ_REL */
#endif

char _license[] SEC("license") = "GPL";
