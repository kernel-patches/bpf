// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "../test_kmods/bpf_testmod_kfunc.h"

extern u64 bpf_rol64(u64 x, u32 n) __ksym;
extern u64 bpf_select64(u64 cond, u64 a, u64 b) __ksym;
extern u64 bpf_extract64(u64 x, u32 start, u32 len) __ksym;
extern u64 bpf_load_be64(const void *p, s32 off) __ksym;
extern void bpf_prefetch(const void *p) __ksym;
extern void bpf_copy16(void *dst, const void *src) __ksym;
extern u64 bpf_lea64(u64 base, u64 index, u32 scale, s32 disp) __ksym;

/* r6 = rol(r6, 13) is one rol, the moves around the call go away */
SEC("tc")
__success __retval(8192)
__xlated("0: r6 = 1")
__xlated("1: call")
__xlated("2: r0 = r6")
__arch_x86_64
__jited("{{.*}}movl\t$0x1, %ebx")
__jited("{{.*}}rolq\t$0xd, %rbx")
__jited("{{.*}}movq\t%rbx, %rax")
__naked void inline_rol64_in_place(void)
{
	asm volatile (
	"r6 = 1;"
	"r1 = r6;"
	"r2 = 13;"
	"call %[bpf_rol64];"
	"r6 = r0;"
	"r0 = r6;"
	"exit;"
	:
	: __imm(bpf_rol64)
	: __clobber_all);
}

/* r7 = rol(r6, 8) keeps r6 */
SEC("tc")
__success __retval(255)
__arch_x86_64
__jited("{{.*}}{{rorxq\t\\$0x38, %rdi, %r13|rolq\t\\$0x8, %r13}}")
__naked void inline_rol64_copy(void)
{
	asm volatile (
	"r6 = 1;"
	"r1 = r6;"
	"r2 = 8;"
	"call %[bpf_rol64];"
	"r7 = r0;"
	"r0 = r7;"
	"r0 -= r6;"
	"exit;"
	:
	: __imm(bpf_rol64)
	: __clobber_all);
}

/* a 32-bit move of the constant goes away as well */
SEC("tc")
__success __retval(16)
__xlated("1: call")
__arch_x86_64
__jited("{{.*}}rolq\t$0x4, %rbx")
__naked void inline_rol_w2(void)
{
	asm volatile (
	"r6 = 1;"
	"r1 = r6;"
	"w2 = 4;"
	"call %[bpf_rol64];"
	"r6 = r0;"
	"r0 = r6;"
	"exit;"
	:
	: __imm(bpf_rol64)
	: __clobber_all);
}

SEC("tc")
__success __retval(42)
__arch_x86_64
__jited("{{.*}}testq\t%rbx, %rbx")
__jited("{{.*}}movq\t%r14, %r15")
__jited("{{.*}}cmovneq\t%r13, %r15")
__naked void inline_select(void)
{
	asm volatile (
	"r6 = 1;"
	"r7 = 42;"
	"r8 = 7;"
	"r1 = r6;"
	"r2 = r7;"
	"r3 = r8;"
	"call %[bpf_select64];"
	"r9 = r0;"
	"r0 = r9;"
	"exit;"
	:
	: __imm(bpf_select64)
	: __clobber_all);
}

/* r9 = r6 ? r7 : r9 is a test and a cmov */
SEC("tc")
__success __retval(7)
__arch_x86_64
__jited("{{.*}}testq\t%rbx, %rbx")
__jited("{{.*}}cmovneq\t%r13, %r15")
__naked void inline_select_in_place(void)
{
	asm volatile (
	"r6 = 0;"
	"r7 = 42;"
	"r9 = 7;"
	"r1 = r6;"
	"r2 = r7;"
	"r3 = r9;"
	"call %[bpf_select64];"
	"r9 = r0;"
	"r0 = r9;"
	"exit;"
	:
	: __imm(bpf_select64)
	: __clobber_all);
}

SEC("tc")
__success __retval(0x56)
__arch_x86_64
__jited("{{.*}}{{bextrq\t%r13, %rbx, %r13|shlq\t%cl, %rbx}}")
__naked void inline_extract(void)
{
	asm volatile (
	"r6 = 0x12345678;"
	"r1 = r6;"
	"r2 = 8;"
	"r3 = 8;"
	"call %[bpf_extract64];"
	"r7 = r0;"
	"r0 = r7;"
	"exit;"
	:
	: __imm(bpf_extract64)
	: __clobber_all);
}

/* the bytes 01..08 on the stack, read as big endian */
SEC("tc")
__success __retval(0x05060708)
__arch_x86_64
__jited("{{.*}}{{movbeq\t\\(%rbx\\), %rax|bswapq\t%rax}}")
__naked void inline_load_be64(void)
{
	asm volatile (
	"*(u32 *)(r10 - 8) = 0x04030201;"
	"*(u32 *)(r10 - 4) = 0x08070605;"
	"r6 = r10;"
	"r6 += -8;"
	"r1 = r6;"
	"r2 = 0;"
	"call %[bpf_load_be64];"
	"exit;"
	:
	: __imm(bpf_load_be64)
	: __clobber_all);
}

SEC("tc")
__success __retval(0)
__arch_x86_64
__jited("{{.*}}prefetcht0\t{{.*}}%r13)")
__naked void inline_prefetch(void)
{
	asm volatile (
	"*(u64 *)(r10 - 8) = 0;"
	"r7 = r10;"
	"r7 += -8;"
	"r1 = r7;"
	"call %[bpf_prefetch];"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_prefetch)
	: __clobber_all);
}

/* the instructions of a prefetch load, so the address must be readable */
SEC("tc")
__failure __msg("R1 invalid mem access 'scalar'")
__naked void inline_prefetch_scalar(void)
{
	asm volatile (
	"r1 = 0;"
	"call %[bpf_prefetch];"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_prefetch)
	: __clobber_all);
}

/* copy 16 bytes from fp-16 to fp-32: the JIT copies the compiled kfunc */
SEC("tc")
__success __retval(0x22)
__arch_x86_64
__xlated("6: call")
__jited("{{.*}}movq\t(%r13), %{{.*}}")
__naked void inline_copy16(void)
{
	asm volatile (
	"*(u64 *)(r10 - 16) = 0x11;"
	"*(u64 *)(r10 - 8) = 0x22;"
	"r6 = r10;"
	"r6 += -32;"
	"r7 = r10;"
	"r7 += -16;"
	"r1 = r6;"
	"r2 = r7;"
	"call %[bpf_copy16];"
	"r0 = *(u64 *)(r10 - 24);"
	"exit;"
	:
	: __imm(bpf_copy16)
	: __clobber_all);
}

/* the verifier checks the memory that the copy touches */
SEC("tc")
__failure __msg("off=0 size=8")
__naked void inline_copy16_out_of_bounds(void)
{
	asm volatile (
	"*(u64 *)(r10 - 8) = 0;"
	"r1 = r10;"
	"r1 += -16;"
	"r2 = r10;"
	"r2 += -8;"
	"call %[bpf_copy16];"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_copy16)
	: __clobber_all);
}

/* 100 + 3 * 4 + 16 */
SEC("tc")
__success __retval(128)
__arch_x86_64
__jited("{{.*}}leaq\t0x10(%rbx,%r13,4), %r14")
__naked void inline_lea(void)
{
	asm volatile (
	"r6 = 100;"
	"r7 = 3;"
	"r1 = r6;"
	"r2 = r7;"
	"r3 = 4;"
	"r4 = 16;"
	"call %[bpf_lea64];"
	"r8 = r0;"
	"r0 = r8;"
	"exit;"
	:
	: __imm(bpf_lea64)
	: __clobber_all);
}

/* the instructions bound the result, a call would not */
SEC("tc")
__success __retval(0)
__naked void inline_precision(void)
{
	asm volatile (
	"call %[bpf_get_prandom_u32];"
	"r1 = r0;"
	"r2 = 0;"
	"r3 = 3;"
	"call %[bpf_extract64];"
	"r6 = r10;"
	"r6 += -8;"
	"r6 += r0;"
	"r0 = 0;"
	"*(u8 *)(r6 + 0) = r0;"
	"exit;"
	:
	: __imm(bpf_get_prandom_u32), __imm(bpf_extract64)
	: __clobber_all);
}

/* arguments cannot be read after the instructions, as after a call */
SEC("tc")
__failure __msg("R1 !read_ok")
__naked void inline_clobber(void)
{
	asm volatile (
	"r1 = 1;"
	"r2 = 42;"
	"r3 = 7;"
	"call %[bpf_select64];"
	"r0 = r1;"
	"exit;"
	:
	: __imm(bpf_select64)
	: __clobber_all);
}

/* a kfunc that returns nothing leaves R0 unreadable after its body */
SEC("tc")
__failure __msg("R0 !read_ok")
__naked void inline_void_r0(void)
{
	asm volatile (
	"r1 = r10;"
	"r1 += -8;"
	"call %[bpf_prefetch];"
	"exit;"
	:
	: __imm(bpf_prefetch)
	: __clobber_all);
}

SEC("tc")
__failure __msg("R2 must be a known constant")
__naked void inline_not_constant(void)
{
	asm volatile (
	"call %[bpf_get_prandom_u32];"
	"r1 = 1;"
	"r2 = r0;"
	"call %[bpf_rol64];"
	"exit;"
	:
	: __imm(bpf_get_prandom_u32), __imm(bpf_rol64)
	: __clobber_all);
}

/* r1 = r6 is skipped by a jump, so it must stay */
SEC("tc")
__success __retval(42)
__naked void inline_bind_jump(void)
{
	asm volatile (
	"r9 = *(u32 *)(r1 + %[len]);"
	"r6 = 0;"
	"r7 = 42;"
	"r8 = 7;"
	"r1 = 1;"
	"if r9 != 0 goto l0_%=;"
	"r1 = r6;"
"l0_%=:"
	"r2 = r7;"
	"r3 = r8;"
	"call %[bpf_select64];"
	"exit;"
	:
	: __imm(bpf_select64),
	  __imm_const(len, offsetof(struct __sk_buff, len))
	: __clobber_all);
}

#if __clang_major__ >= 18 || defined(__BPF_FEATURE_MOVSX)
/* a sign-extending move is not a plain copy of R6 */
SEC("tc")
__success __retval(7)
__naked void inline_bind_movsx(void)
{
	asm volatile (
	"r6 = 0x100;"
	"r7 = 42;"
	"r8 = 7;"
	"r1 = (s8)r6;"
	"r2 = r7;"
	"r3 = r8;"
	"call %[bpf_select64];"
	"exit;"
	:
	: __imm(bpf_select64)
	: __clobber_all);
}
#endif

/* the result takes the register of the condition */
SEC("tc")
__success __retval(42)
__naked void inline_bind_shared(void)
{
	asm volatile (
	"r6 = 1;"
	"r7 = 42;"
	"r8 = 7;"
	"r1 = r6;"
	"r2 = r7;"
	"r3 = r8;"
	"call %[bpf_select64];"
	"r6 = r0;"
	"r0 = r6;"
	"exit;"
	:
	: __imm(bpf_select64)
	: __clobber_all);
}

/* native code from a module, with the result in the register of an argument */
SEC("tc")
__success __retval(6)
__arch_x86_64
__xlated("2: call")
__jited("{{.*}}xorq\t%r13, %rbx")
__naked void inline_module(void)
{
	asm volatile (
	"r6 = 5;"
	"r7 = 3;"
	"r1 = r6;"
	"r2 = r7;"
	"call %[bpf_testmod_inline_xor];"
	"r6 = r0;"
	"r0 = r6;"
	"exit;"
	:
	: __imm(bpf_testmod_inline_xor)
	: __clobber_all);
}

/* without emit, the JIT copies the compiled kfunc, with the registers bound */
SEC("tc")
__success __retval(5)
__arch_x86_64
__xlated("1: call")
__jited("{{.*}}movq\t%rbx, %r13")
__naked void inline_copy(void)
{
	asm volatile (
	"r6 = 5;"
	"r1 = r6;"
	"call %[bpf_testmod_inline_mov];"
	"r7 = r0;"
	"r0 = r7;"
	"exit;"
	:
	: __imm(bpf_testmod_inline_mov)
	: __clobber_all);
}

/* compiled code that branches or divides is not copied: the instructions stay */
SEC("tc")
__success __retval(0)
__xlated("{{.*}}r0 /= r2")
__naked void inline_copy_div(void)
{
	asm volatile (
	"r1 = 9;"
	"r2 = 0;"
	"call %[bpf_testmod_inline_div];"
	"exit;"
	:
	: __imm(bpf_testmod_inline_div)
	: __clobber_all);
}

/* a kfunc that the program may not call keeps its call, which is rejected */
SEC("xdp")
__failure __msg("calling kernel function bpf_testmod_inline_mov is not allowed")
__naked void inline_not_allowed(void)
{
	asm volatile (
	"r1 = 1;"
	"call %[bpf_testmod_inline_mov];"
	"exit;"
	:
	: __imm(bpf_testmod_inline_mov)
	: __clobber_all);
}

#define ROL(x, n) ((x) << ((n) & 63) | (x) >> (-(n) & 63))

struct diff_state {
	u64 bad;
	u8 src[64], dst[64];
};

static u64 rand64(void)
{
	return (u64)bpf_get_prandom_u32() << 32 | bpf_get_prandom_u32();
}

/* a global function, so that the verifier checks it once and not per call */
__noinline int diff_step(struct diff_state *s)
{
	u64 x = rand64(), y = rand64(), a = rand64(), b = rand64();
	int i;

	if (!s)
		return 0;
	s->bad |= (bpf_rol64(x, 1) ^ ROL(x, 1)) | (bpf_rol64(x, 13) ^ ROL(x, 13)) |
		  (bpf_rol64(x, 63) ^ ROL(x, 63)) | (bpf_rol64(x, 64) ^ x);
	s->bad |= bpf_select64(x & 1, a, b) ^ (x & 1 ? a : b);
	s->bad |= bpf_extract64(x, 0, 64) ^ x;
	s->bad |= bpf_extract64(x, 13, 7) ^ (x >> 13 & 0x7f);
	s->bad |= bpf_extract64(x, 40, 24) ^ (x >> 40);
	s->bad |= bpf_extract64(x, 63, 1) ^ (x >> 63);
	s->bad |= bpf_lea64(x, y, 8, -12345) ^ (x + y * 8 - 12345);
	for (i = 0; i < 8; i++) {
		s->src[i] = x >> (8 * i);
		s->src[8 + i] = y >> (8 * i);
	}
	s->bad |= bpf_load_be64(s->src, 0) ^ __builtin_bswap64(x);
	s->bad |= bpf_load_be64(s->src + 16, -8) ^ __builtin_bswap64(y);
	/* unaligned */
	s->bad |= bpf_load_be64(s->src + 8, -7) ^ __builtin_bswap64(x >> 8 | y << 56);
	bpf_copy16(s->dst + 8, s->src);
	for (i = 0; i < 16; i++)
		s->bad |= s->dst[8 + i] ^ s->src[i];
	return 0;
}

/* native code and the instructions agree on random inputs */
SEC("tc")
__success __retval(0)
int inline_differential(struct __sk_buff *skb)
{
	struct diff_state s = {};
	int i;

	for (i = 0; i < 256; i++)
		diff_step(&s);
	return s.bad != 0;
}

/* emits BTF for the kfuncs that only inline assembly calls */
void __kfunc_btf_root(void)
{
	bpf_prefetch(0);
	bpf_testmod_inline_mov(0);
	bpf_testmod_inline_xor(0, 0);
	bpf_testmod_inline_div(0, 0);
}

char _license[] SEC("license") = "GPL";
