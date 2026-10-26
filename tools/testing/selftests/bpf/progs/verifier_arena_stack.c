// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "../../../include/linux/filter.h"
#include "bpf_misc.h"

#if defined(__TARGET_ARCH_x86) || defined(__TARGET_ARCH_arm64)

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 64);
} arena SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} jmp_table SEC(".maps");

/* Compilers don't know r12 yet */
#define R12 12
/* r12 += n */
#define ADJ(n)		BPF_RAW_INSN(BPF_ALU64 | BPF_ADD | BPF_K, R12, 0, 0, n)
/* dst = r12 */
#define MOV(dst)	BPF_RAW_INSN(BPF_ALU64 | BPF_MOV | BPF_X, dst, R12, 0, 0)
/* dst = *(sz *)(r12 + off) */
#define LDX(sz, dst, off) BPF_RAW_INSN(BPF_LDX | BPF_MEM | sz, dst, R12, off, 0)
#define LDSX(sz, dst, off) BPF_RAW_INSN(BPF_LDX | BPF_MEMSX | sz, dst, R12, off, 0)
/* *(sz *)(r12 + off) = src */
#define STX(sz, off, src) BPF_RAW_INSN(BPF_STX | BPF_MEM | sz, R12, src, off, 0)
/* *(sz *)(r12 + off) = imm */
#define ST(sz, off, imm) BPF_RAW_INSN(BPF_ST | BPF_MEM | sz, R12, 0, off, imm)
/* dst = addr_space_cast(dst, 0, 1) */
#define CAST_KERN(dst)	BPF_RAW_INSN(BPF_ALU64 | BPF_MOV | BPF_X, dst, dst, BPF_ADDR_SPACE_CAST, 1)

SEC("syscall")
__description("arena stack: load and store")
__success __retval(12)
__xlated("r0 = *(u64 *)(r12 -16)")
__xlated("r2 = *(u64 *)(r12 -8)")
__naked void load_store(void)
{
	asm volatile (
	".8byte %[adj];"
	".8byte %[st];"		/* *(u64 *)(r12 - 16) = 7 */
	"r1 = 5;"
	".8byte %[stx];"	/* *(u64 *)(r12 - 8) = r1 */
	".8byte %[ldx0];"	/* r0 = *(u64 *)(r12 - 16) */
	".8byte %[ldx1];"	/* r2 = *(u64 *)(r12 - 8) */
	"r0 += r2;"
	"exit;"
	:
	: __imm_insn(adj, ADJ(16)),
	  __imm_insn(st, ST(BPF_DW, -16, 7)),
	  __imm_insn(stx, STX(BPF_DW, -8, BPF_REG_1)),
	  __imm_insn(ldx0, LDX(BPF_DW, BPF_REG_0, -16)),
	  __imm_insn(ldx1, LDX(BPF_DW, BPF_REG_2, -8))
	: __clobber_all);
}

SEC("syscall")
__description("arena stack: every size, sign extension")
__success __retval(0)
__naked void sizes(void)
{
	asm volatile (
	".8byte %[adj];"
	"r1 = 0x8899aabb ll;"
	".8byte %[stx];"	/* *(u64 *)(r12 - 16) = r1 */
	"r0 = 1;"
	".8byte %[ldx_b];"
	"if r2 != 0xbb goto 1f;"
	"r0 = 2;"
	".8byte %[ldx_h];"
	"if r2 != 0xaabb goto 1f;"
	"r0 = 3;"
	".8byte %[ldx_w];"
	"r3 = 0x8899aabb ll;"
	"if r2 != r3 goto 1f;"
	"r0 = 4;"
	".8byte %[ldsx_w];"
	"if r2 s>= 0 goto 1f;"
	"r0 = 5;"
	".8byte %[st_b];"	/* *(u8 *)(r12 - 15) = 0 */
	".8byte %[ldx_h];"
	"if r2 != 0xbb goto 1f;"
	"r0 = 0;"
"1:"
	"exit;"
	:
	: __imm_insn(adj, ADJ(16)),
	  __imm_insn(stx, STX(BPF_DW, -16, BPF_REG_1)),
	  __imm_insn(ldx_b, LDX(BPF_B, BPF_REG_2, -16)),
	  __imm_insn(ldx_h, LDX(BPF_H, BPF_REG_2, -16)),
	  __imm_insn(ldx_w, LDX(BPF_W, BPF_REG_2, -16)),
	  __imm_insn(ldsx_w, LDSX(BPF_W, BPF_REG_2, -16)),
	  __imm_insn(st_b, ST(BPF_B, -15, 0))
	: __clobber_all);
}

SEC("syscall")
__description("arena stack: rX = r12 is the address of the frame")
__success __retval(9)
__naked void address(void)
{
	asm volatile (
	".8byte %[adj];"
	".8byte %[mov];"	/* r1 = r12 */
	"r1 += -8;"
	".8byte %[cast];"
	"r2 = 9;"
	"*(u64 *)(r1 + 0) = r2;"
	".8byte %[ldx];"	/* r0 = *(u64 *)(r12 - 8) */
	"exit;"
	:
	: __imm_insn(adj, ADJ(16)),
	  __imm_insn(mov, MOV(BPF_REG_1)),
	  __imm_insn(cast, CAST_KERN(BPF_REG_1)),
	  __imm_insn(ldx, LDX(BPF_DW, BPF_REG_0, -8))
	: __clobber_all);
}

static __naked __noinline __used long callee_with_frame(void)
{
	asm volatile (
	".8byte %[adj];"
	".8byte %[st0];"
	".8byte %[st1];"
	".8byte %[ldx];"
	"exit;"
	:
	: __imm_insn(adj, ADJ(16)),
	  __imm_insn(st0, ST(BPF_DW, -16, 10)),
	  __imm_insn(st1, ST(BPF_DW, -8, 10)),
	  __imm_insn(ldx, LDX(BPF_DW, BPF_REG_0, -16))
	: __clobber_all);
}

SEC("syscall")
__description("arena stack: the frame of the callee is above")
__success __retval(21)
__naked void call(void)
{
	asm volatile (
	".8byte %[adj];"
	".8byte %[st];"		/* *(u64 *)(r12 - 16) = 1 */
	"call callee_with_frame;"
	"r6 = r0;"
	"call callee_with_frame;"
	"r0 += r6;"
	".8byte %[ldx];"	/* r1 = *(u64 *)(r12 - 16) */
	"r0 += r1;"
	"exit;"
	:
	: __imm_insn(adj, ADJ(16)),
	  __imm_insn(st, ST(BPF_DW, -16, 1)),
	  __imm_insn(ldx, LDX(BPF_DW, BPF_REG_1, -16))
	: __clobber_all);
}

/* no frame of its own, r12 goes through */
static __naked __noinline __used long callee_in_the_middle(void)
{
	asm volatile (
	"call %[bpf_get_prandom_u32];"
	"call callee_with_frame;"
	"exit;"
	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("syscall")
__description("arena stack: a function without a frame in the middle")
__success __retval(11)
__naked void call_through(void)
{
	asm volatile (
	".8byte %[adj];"
	".8byte %[st];"
	"call callee_in_the_middle;"
	".8byte %[ldx];"
	"r0 += r1;"
	"exit;"
	:
	: __imm_insn(adj, ADJ(16)),
	  __imm_insn(st, ST(BPF_DW, -16, 1)),
	  __imm_insn(ldx, LDX(BPF_DW, BPF_REG_1, -16))
	: __clobber_all);
}

SEC("syscall")
__description("arena stack: helpers don't change r12")
__success __retval(3)
__naked void helper(void)
{
	asm volatile (
	".8byte %[adj];"
	".8byte %[st];"
	"call %[bpf_get_prandom_u32];"
	"call %[bpf_ktime_get_ns];"
	".8byte %[ldx];"
	"exit;"
	:
	: __imm(bpf_get_prandom_u32),
	  __imm(bpf_ktime_get_ns),
	  __imm_insn(adj, ADJ(16)),
	  __imm_insn(st, ST(BPF_DW, -16, 3)),
	  __imm_insn(ldx, LDX(BPF_DW, BPF_REG_0, -16))
	: __clobber_all);
}

static __naked __noinline __used long recurses(long n)
{
	asm volatile (
	".8byte %[adj];"
	".8byte %[stx32];"
	".8byte %[stx8];"
	"if r1 == 0 goto 1f;"
	"r1 += -1;"
	"call recurses;"
"1:"
	"r0 = 0;"
	"exit;"
	:
	: __imm_insn(adj, ADJ(32)),
	  __imm_insn(stx32, STX(BPF_DW, -32, BPF_REG_1)),
	  __imm_insn(stx8, STX(BPF_DW, -8, BPF_REG_1))
	: __clobber_all);
}

SEC("syscall")
__description("arena stack: r12 after the recursion ran out of budget")
__success __retval(0)
__naked void recursion(void)
{
	asm volatile (
	".8byte %[adj];"
	".8byte %[st];"		/* *(u64 *)(r12 - 8) = 4660 */
	".8byte %[mov6];"	/* r6 = r12 */
	"r1 = 100000;"
	"call recurses;"
	".8byte %[mov7];"	/* r7 = r12 */
	"r0 = 1;"
	"if r6 != r7 goto 1f;"
	"r0 = 2;"
	".8byte %[ldx];"	/* r1 = *(u64 *)(r12 - 8) */
	"if r1 != 4660 goto 1f;"
	"r0 = 0;"
"1:"
	"exit;"
	:
	: __imm_insn(adj, ADJ(16)),
	  __imm_insn(st, ST(BPF_DW, -8, 4660)),
	  __imm_insn(mov6, MOV(BPF_REG_6)),
	  __imm_insn(mov7, MOV(BPF_REG_7)),
	  __imm_insn(ldx, LDX(BPF_DW, BPF_REG_1, -8))
	: __clobber_all);
}

static __naked __noinline __used long store_through(long addr)
{
	asm volatile (
	".8byte %[adj];"
	".8byte %[st];"
	".8byte %[cast];"
	"r2 = 5;"
	"*(u64 *)(r1 + 0) = r2;"
	"r0 = 0;"
	"exit;"
	:
	: __imm_insn(adj, ADJ(64)),
	  __imm_insn(st, ST(BPF_DW, -64, 77)),
	  __imm_insn(cast, CAST_KERN(BPF_REG_1))
	: __clobber_all);
}

SEC("syscall")
__description("arena stack: the callee writes to the frame of the caller")
__success __retval(5)
__naked void pass_address(void)
{
	asm volatile (
	".8byte %[adj];"
	".8byte %[mov];"
	"r1 += -16;"
	"call store_through;"
	".8byte %[ldx];"
	"exit;"
	:
	: __imm_insn(adj, ADJ(16)),
	  __imm_insn(mov, MOV(BPF_REG_1)),
	  __imm_insn(ldx, LDX(BPF_DW, BPF_REG_0, -16))
	: __clobber_all);
}

static __naked __noinline __used long unwinds(void)
{
	asm volatile (
	".8byte %[adj];"
	".8byte %[st];"
	"r0 = 0;"
	".8byte %[unwind_exit];"
	:
	: __imm_insn(adj, ADJ(32)),
	  __imm_insn(st, ST(BPF_DW, -32, -1)),
	  __imm_insn(unwind_exit, BPF_RAW_INSN(BPF_JMP | BPF_EXIT, 0, BPF_UNWIND_EXIT, 0, 0))
	: __clobber_all);
}

/* its pad only carries on */
static __naked __noinline __used long unwinds_through(void)
{
	asm volatile (
	".8byte %[adj];"
	"call unwinds;"
	".8byte %[unwind_goto];"
	"r0 = 0;"
	"exit;"
	".8byte %[unwind_exit];"
	:
	: __imm_insn(adj, ADJ(16)),
	  __imm_insn(unwind_goto, BPF_RAW_INSN(BPF_JMP | BPF_JCOND, 0, BPF_UNWIND_GOTO, 2, 0)),
	  __imm_insn(unwind_exit, BPF_RAW_INSN(BPF_JMP | BPF_EXIT, 0, BPF_UNWIND_EXIT, 0, 0))
	: __clobber_all);
}

SEC("syscall")
__description("arena stack: r12 in the landing pad")
__success __retval(5)
__naked void unwind(void)
{
	asm volatile (
	".8byte %[adj];"
	".8byte %[st];"		/* *(u64 *)(r12 - 16) = 5 */
	"call unwinds_through;"
	".8byte %[unwind_goto];"
	"r0 = 1;"
	"exit;"
	".8byte %[ldx];"	/* r0 = *(u64 *)(r12 - 16) */
	"exit;"
	:
	: __imm_insn(adj, ADJ(16)),
	  __imm_insn(st, ST(BPF_DW, -16, 5)),
	  __imm_insn(unwind_goto, BPF_RAW_INSN(BPF_JMP | BPF_JCOND, 0, BPF_UNWIND_GOTO, 2, 0)),
	  __imm_insn(ldx, LDX(BPF_DW, BPF_REG_0, -16))
	: __clobber_all);
}

#ifdef __BPF_FEATURE_STACK_ARGUMENT

extern __u64 bpf_kfunc_call_stack_arg(__u64 a, __u64 b, __u64 c, __u64 d, __u64 e, __u64 f,
				      __u64 g, __u64 h, __u64 i, __u64 j) __ksym;

/* BTF FUNC records are not generated for kfuncs referenced from inline assembly */
void __kfunc_btf_root(void)
{
	bpf_kfunc_call_stack_arg(0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
}

static __naked __noinline __used
long callee_7args(long a, long b, long c, long d, long e, long f, long g)
{
	asm volatile (
	".8byte %[adj];"
	"r0 = *(u64 *)(r11 + 8);"
	".8byte %[stx0];"	/* *(u64 *)(r12 - 16) = f */
	"r0 = *(u64 *)(r11 + 16);"
	".8byte %[stx8];"	/* *(u64 *)(r12 - 8) = g */
	"r6 = r5;"
	"call %[bpf_get_prandom_u32];"
	".8byte %[ldx0];"
	".8byte %[ldx8];"
	"r0 *= 10;"
	"r0 += r1;"
	"r0 *= 10;"
	"r0 += r6;"
	"exit;"
	:
	: __imm(bpf_get_prandom_u32),
	  __imm_insn(adj, ADJ(16)),
	  __imm_insn(stx0, STX(BPF_DW, -16, BPF_REG_0)),
	  __imm_insn(stx8, STX(BPF_DW, -8, BPF_REG_0)),
	  __imm_insn(ldx0, LDX(BPF_DW, BPF_REG_0, -16)),
	  __imm_insn(ldx8, LDX(BPF_DW, BPF_REG_1, -8))
	: __clobber_all);
}

SEC("syscall")
__description("arena stack: a function with 7 arguments")
__success __retval(1675)
__naked void stack_args(void)
{
	asm volatile (
	".8byte %[adj];"
	".8byte %[st];"		/* *(u64 *)(r12 - 16) = 1000 */
	"r1 = 1;"
	"r2 = 2;"
	"r3 = 3;"
	"r4 = 4;"
	"r5 = 5;"
	"*(u64 *)(r11 - 16) = 7;"
	"*(u64 *)(r11 - 8) = 6;"
	"call callee_7args;"
	".8byte %[ldx];"
	"r0 += r1;"
	"exit;"
	:
	: __imm_insn(adj, ADJ(16)),
	  __imm_insn(st, ST(BPF_DW, -16, 1000)),
	  __imm_insn(ldx, LDX(BPF_DW, BPF_REG_1, -16))
	: __clobber_all);
}

SEC("tc")
__description("arena stack: a kfunc with 10 arguments")
__success __retval(1055)
__naked void kfunc_stack_args(void)
{
	asm volatile (
	".8byte %[adj];"
	".8byte %[st];"		/* *(u64 *)(r12 - 16) = 1000 */
	"r1 = 1;"
	"r2 = 2;"
	"r3 = 3;"
	"r4 = 4;"
	"r5 = 5;"
	"*(u64 *)(r11 - 40) = 10;"
	"*(u64 *)(r11 - 32) = 9;"
	"*(u64 *)(r11 - 24) = 8;"
	"*(u64 *)(r11 - 16) = 7;"
	"*(u64 *)(r11 - 8) = 6;"
	"call %[bpf_kfunc_call_stack_arg];"
	".8byte %[ldx];"
	"r0 += r1;"
	"exit;"
	:
	: __imm(bpf_kfunc_call_stack_arg),
	  __imm_insn(adj, ADJ(16)),
	  __imm_insn(st, ST(BPF_DW, -16, 1000)),
	  __imm_insn(ldx, LDX(BPF_DW, BPF_REG_1, -16))
	: __clobber_all);
}

#endif /* __BPF_FEATURE_STACK_ARGUMENT */

SEC("syscall")
__description("arena stack: what is loaded is a number")
__failure __msg("R1 invalid mem access 'scalar'")
__naked void loaded_is_number(void)
{
	asm volatile (
	".8byte %[adj];"
	"r1 = r10;"
	".8byte %[stx];"
	".8byte %[ldx];"
	"r0 = *(u64 *)(r1 - 8);"
	"exit;"
	:
	: __imm_insn(adj, ADJ(16)),
	  __imm_insn(stx, STX(BPF_DW, -16, BPF_REG_1)),
	  __imm_insn(ldx, LDX(BPF_DW, BPF_REG_1, -16))
	: __clobber_all);
}

SEC("syscall")
__description("arena stack: rX = r12 is a number")
__failure __msg("R1 invalid mem access 'scalar'")
__naked void address_is_number(void)
{
	asm volatile (
	".8byte %[adj];"
	".8byte %[mov];"
	"r0 = *(u64 *)(r1 + 0);"
	"exit;"
	:
	: __imm_insn(adj, ADJ(16)),
	  __imm_insn(mov, MOV(BPF_REG_1))
	: __clobber_all);
}

#define BAD_INSN(name, desc, msg, first, second)			\
SEC("syscall")								\
__description("arena stack: " desc)					\
__failure __msg(msg)							\
__naked void name(void)							\
{									\
	asm volatile (							\
	".8byte %[first_insn];"						\
	".8byte %[second_insn];"					\
	"r0 = 0;"							\
	"exit;"								\
	:								\
	: __imm_insn(first_insn, first),				\
	  __imm_insn(second_insn, second)				\
	: __clobber_all);						\
}

#define NOP BPF_MOV64_IMM(BPF_REG_1, 0)

BAD_INSN(adj_not_first, "r12 += 16 is not the first insn",
	 "R12 can be changed by the first insn of a function only", NOP, ADJ(16))
BAD_INSN(adj_twice, "r12 += 16 twice",
	 "R12 can be changed by the first insn of a function only", ADJ(16), ADJ(16))
BAD_INSN(adj_negative, "r12 += -16", "invalid size of the frame", ADJ(-16), NOP)
BAD_INSN(adj_zero, "r12 += 0", "invalid size of the frame", ADJ(0), NOP)
BAD_INSN(adj_unaligned, "r12 += 8", "invalid size of the frame", ADJ(8), NOP)
BAD_INSN(adj_large, "r12 += 32784", "invalid size of the frame", ADJ(32784), NOP)
BAD_INSN(mov_to, "r12 = r1", "R12 is invalid", NOP, BPF_MOV64_REG(R12, BPF_REG_1))
BAD_INSN(mov_imm, "r12 = 0", "R12 is invalid", NOP, BPF_MOV64_IMM(R12, 0))
BAD_INSN(add_reg, "r12 += r1", "R12 is invalid", NOP, BPF_ALU64_REG(BPF_ADD, R12, BPF_REG_1))
BAD_INSN(adj32, "w12 += 16", "R12 is invalid", BPF_ALU32_IMM(BPF_ADD, R12, 16), NOP)
BAD_INSN(sub_imm, "r12 -= 16", "R12 is invalid", BPF_ALU64_IMM(BPF_SUB, R12, 16), NOP)
BAD_INSN(add_from, "r1 += r12", "R12 is invalid", NOP, BPF_ALU64_REG(BPF_ADD, BPF_REG_1, R12))
BAD_INSN(mov32_from, "w1 = w12", "R12 is invalid", NOP, BPF_MOV32_REG(BPF_REG_1, R12))
BAD_INSN(load_to, "r12 = *(u64 *)(r10 - 8)", "R12 is invalid", NOP,
	 BPF_LDX_MEM(BPF_DW, R12, BPF_REG_10, -8))
BAD_INSN(store_from, "*(u64 *)(r10 - 8) = r12", "R12 is invalid", NOP,
	 BPF_STX_MEM(BPF_DW, BPF_REG_10, R12, -8))
BAD_INSN(store_itself, "*(u64 *)(r12 - 8) = r12", "R12 is invalid", NOP,
	 BPF_STX_MEM(BPF_DW, R12, R12, -8))
BAD_INSN(atomic, "lock *(u64 *)(r12 - 8) += r1", "R12 is invalid", NOP,
	 BPF_ATOMIC_OP(BPF_DW, BPF_ADD, R12, BPF_REG_1, -8))
BAD_INSN(jump, "if r12 == 0 goto", "R12 is invalid", NOP, BPF_JMP_IMM(BPF_JEQ, R12, 0, 0))
BAD_INSN(r13, "r1 = r13", "R13 is invalid", NOP, BPF_MOV64_REG(BPF_REG_1, 13))
BAD_INSN(local_atomic, "atomic that is local to the cpu", "BPF_ATOMIC uses invalid atomic opcode",
	 BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
	 BPF_ATOMIC_OP(BPF_DW, BPF_ADD | BPF_FETCH | 0x1000, BPF_REG_10, BPF_REG_1, -8))

SEC("syscall")
__description("arena stack: jump to r12 += 16")
__failure __msg("jump to the insn that changes R12")
__naked void jump_to_adj(void)
{
	asm volatile (
"1:"
	".8byte %[adj];"
	"call %[bpf_get_prandom_u32];"
	"if r0 != 0 goto 1b;"
	"exit;"
	:
	: __imm(bpf_get_prandom_u32),
	  __imm_insn(adj, ADJ(16))
	: __clobber_all);
}

/* adds the index and what the context points to, through its frame */
static __naked __noinline __used long loop_cb(void)
{
	asm volatile (
	".8byte %[adj];"
	".8byte %[stx16];"	/* *(u64 *)(r12 - 16) = r1 */
	"r4 = *(u64 *)(r2 + 0);"
	".8byte %[ldx16];"	/* r5 = *(u64 *)(r12 - 16) */
	"r4 += r5;"
	"*(u64 *)(r2 + 0) = r4;"
	"r0 = 0;"
	"exit;"
	:
	: __imm_insn(adj, ADJ(16)),
	  __imm_insn(stx16, STX(BPF_DW, -16, BPF_REG_1)),
	  __imm_insn(ldx16, LDX(BPF_DW, BPF_REG_5, -16))
	: __clobber_all);
}

SEC("syscall")
__description("arena stack: r12 in a callback")
__success __retval(145)
__naked void callback(void)
{
	asm volatile (
	".8byte %[adj];"
	".8byte %[st];"		/* *(u64 *)(r12 - 8) = 100 */
	"r1 = 0;"
	"*(u64 *)(r10 - 8) = r1;"
	"r1 = 10;"
	"r2 = loop_cb ll;"
	"r3 = r10;"
	"r3 += -8;"
	"r4 = 0;"
	"call %[bpf_loop];"
	/* 0 + 1 + ... + 9 and what is in the frame of the main program */
	"r0 = *(u64 *)(r10 - 8);"
	".8byte %[ldx];"	/* r1 = *(u64 *)(r12 - 8) */
	"r0 += r1;"
	"exit;"
	:
	: __imm(bpf_loop),
	  __imm_insn(adj, ADJ(16)),
	  __imm_insn(st, ST(BPF_DW, -8, 100)),
	  __imm_insn(ldx, LDX(BPF_DW, BPF_REG_1, -8))
	: __clobber_all);
}

SEC("tc")
__description("arena stack: tail call")
__failure __msg("tail_calls are not allowed in programs that use R12")
__naked void tail_call(void)
{
	asm volatile (
	".8byte %[adj];"
	"r2 = %[jmp_table] ll;"
	"r3 = 0;"
	"call %[bpf_tail_call];"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_tail_call),
	  __imm_addr(jmp_table),
	  __imm_insn(adj, ADJ(16))
	: __clobber_all);
}

static __naked __noinline __used long frame_16(void)
{
	asm volatile (
	".8byte %[adj];"
	"r0 = 0;"
	"exit;"
	:
	: __imm_insn(adj, ADJ(16))
	: __clobber_all);
}

static __naked __noinline __used long frame_16k_calls_16(void)
{
	asm volatile (
	".8byte %[adj];"
	"call frame_16;"
	"exit;"
	:
	: __imm_insn(adj, ADJ(16384))
	: __clobber_all);
}

static __naked __noinline __used long frame_16k(void)
{
	asm volatile (
	".8byte %[adj];"
	".8byte %[st];"
	".8byte %[ldx];"
	"exit;"
	:
	: __imm_insn(adj, ADJ(16384)),
	  __imm_insn(st, ST(BPF_DW, -16384, 4)),
	  __imm_insn(ldx, LDX(BPF_DW, BPF_REG_0, -16384))
	: __clobber_all);
}

SEC("syscall")
__description("arena stack: 32K")
__success __retval(4)
__naked void depth_max(void)
{
	asm volatile (
	".8byte %[adj];"
	"call frame_16k;"
	"exit;"
	:
	: __imm_insn(adj, ADJ(16384))
	: __clobber_all);
}

SEC("syscall")
__description("arena stack: more than 32K")
__failure __msg("combined size of the frames in the stack in arena is 32784. Too large")
__naked void depth_too_large(void)
{
	asm volatile (
	".8byte %[adj];"
	"call frame_16k_calls_16;"
	"exit;"
	:
	: __imm_insn(adj, ADJ(16384))
	: __clobber_all);
}

#endif

char _license[] SEC("license") = "GPL";
