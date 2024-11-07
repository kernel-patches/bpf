#include <linux/bpf.h>

#define __imm(name) [name]"i"(name)

__bpf_kfunc int bpf_test_inline_kfunc1(int p);
__bpf_kfunc int bpf_test_inline_kfunc2(int *p);
__bpf_kfunc int bpf_test_inline_kfunc3(void *p, u64 p__sz);
__bpf_kfunc int bpf_test_inline_kfunc4(void);
__bpf_kfunc int bpf_test_inline_kfunc5(struct bpf_dynptr *d);
__bpf_kfunc int bpf_test_inline_kfunc6(void);
__bpf_kfunc int bpf_test_inline_kfunc7(void);
__bpf_kfunc int bpf_test_inline_kfunc8(void);

#ifdef __FOR_BPF
__attribute__((naked))
int bpf_test_inline_kfunc1(int p)
{
	asm volatile (
		"r0 = 42;"
		"if r1 != 1 goto +1;"
		"r0 = 11;"
		"if r1 != 2 goto +1;"
		"r0 = 22;"
		"exit;"
	);
}

__attribute__((naked))
int bpf_test_inline_kfunc2(int *p)
{
	asm volatile (
		"r0 = 42;"
		"if r1 != 0 goto +1;"
		"r0 = 24;"
		"exit;"
	);
}

__attribute__((naked))
int bpf_test_inline_kfunc3(void *p, u64 p__sz)
{
	asm volatile (
		"r1 = *(u64 *)(r1 + 0);"
		"*(u64 *)(r1 + 0) = 42;"
		"r0 = 0;"
		"exit;"
	);
}

__attribute__((naked))
int bpf_test_inline_kfunc4(void)
{
	asm volatile (
		"r0 = 0;"
		"r1 = 1;"
		"r2 = 2;"
		"r6 = 3;"
		"r7 = 4;"
		"exit;"
	);
}

__attribute__((naked))
int bpf_test_inline_kfunc5(struct bpf_dynptr *d)
{
	asm volatile (
		"   r1 = *(u32 *)(r1 + 8);"
		"   r1 &= %[INV_RDONLY_BIT];"
		"   r1 >>= %[TYPE_SHIFT];"
		"   if r1 != %[BPF_DYNPTR_TYPE_SKB] goto 1f;"
		"   r0 = 1;"
		"   goto 3f;"
		"1: if r1 != %[BPF_DYNPTR_TYPE_XDP] goto 2f;"
		"   r0 = 2;"
		"   goto 3f;"
		"2: r0 = 3;"
		"3: exit;"
	:: __imm(BPF_DYNPTR_TYPE_SKB),
	   __imm(BPF_DYNPTR_TYPE_XDP),
	   [INV_RDONLY_BIT]"i"(~DYNPTR_RDONLY_BIT),
	   [TYPE_SHIFT]"i"(DYNPTR_TYPE_SHIFT));
}

__attribute__((naked))
int bpf_test_inline_kfunc6(void)
{
	asm volatile (
		"r0 = 0;"
		"*(u64 *)(r10 - 8) = r0;"
		"r0 = *(u64 *)(r10 - 8);"
		"r6 = 1;"
		"exit;"
	);
}

__attribute__((naked))
int bpf_test_inline_kfunc7(void)
{
	asm volatile (
		"r0 = 0;"
		"*(u64 *)(r10 - 8) = r10;"
		"exit;"
	);
}

__attribute__((naked))
int bpf_test_inline_kfunc8(void)
{
	asm volatile (
		"r0 = 0;"
		"r1 = r10;"
		"exit;"
	);
}

#endif  /* __FOR_BPF */

#ifndef __FOR_BPF

/* Only interested in BPF assembly bodies of these functions, keep dummy bodies */
__bpf_kfunc int bpf_test_inline_kfunc1(int p) { return 0; }
__bpf_kfunc int bpf_test_inline_kfunc2(int *p) { return 0; }
__bpf_kfunc int bpf_test_inline_kfunc3(void *p, u64 p__sz) { return 0; }
__bpf_kfunc int bpf_test_inline_kfunc4(void) { return 0; }
__bpf_kfunc int bpf_test_inline_kfunc5(struct bpf_dynptr *p) { return 0; }
__bpf_kfunc int bpf_test_inline_kfunc6(void) { return 0; }
__bpf_kfunc int bpf_test_inline_kfunc7(void) { return 0; }
__bpf_kfunc int bpf_test_inline_kfunc8(void) { return 0; }

#endif /* __FOR_BPF not defined */

MODULE_LICENSE("Dual BSD/GPL");
