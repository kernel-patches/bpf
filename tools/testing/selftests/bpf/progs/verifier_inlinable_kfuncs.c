#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "bpf_misc.h"
#include <stdbool.h>
#include "bpf_kfuncs.h"

extern int bpf_test_inline_kfunc1(int p) __ksym;
extern int bpf_test_inline_kfunc2(int *p) __ksym;
extern int bpf_test_inline_kfunc3(void *p, __u64 p__sz) __ksym;
extern int bpf_test_inline_kfunc4(void) __ksym;
extern int bpf_test_inline_kfunc5(const struct bpf_dynptr *p) __ksym;
extern int bpf_test_inline_kfunc6(void) __ksym;
extern int bpf_test_inline_kfunc7(void) __ksym;
extern int bpf_test_inline_kfunc8(void) __ksym;

SEC("socket")
/* verify that scalar params are marked as precise */
__log_level(2)
/* first call to kfunc */
__msg("1: (85) call bpf_test_inline_kfunc1")
__msg("mark_precise: frame0: last_idx 1 first_idx 0 subseq_idx -1")
__msg("mark_precise: frame0: regs=r1 stack= before 0: (b7) r1 = 1")
/* second call to kfunc */
__msg("3: (85) call bpf_test_inline_kfunc1")
__msg("mark_precise: frame0: last_idx 3 first_idx 0 subseq_idx -1")
__msg("mark_precise: frame0: regs=r1 stack= before 2: (b7) r1 = 2")
/* check that dead code elimination took place independently for both callsites */
__xlated("0: r1 = 1")
__xlated("1: r0 = 42")
__xlated("2: r0 = 11")
__xlated("3: goto pc+0")
__xlated("4: r1 = 2")
__xlated("5: r0 = 42")
__xlated("6: r0 = 22")
__xlated("7: goto pc+0")
__xlated("8: exit")
__success
__naked void two_callsites_scalar_param(void)
{
	asm volatile (
		"r1 = 1;"
		"call %[bpf_test_inline_kfunc1];"
		"r1 = 2;"
		"call %[bpf_test_inline_kfunc1];"
		"exit;"
		:
		: __imm(bpf_test_inline_kfunc1)
		: __clobber_all
	);
}

SEC("socket")
__xlated("0: r1 = 0")
__xlated("1: r0 = 42")
__xlated("2: r0 = 24")
__xlated("3: goto pc+0")
__xlated("4: exit")
__success
__naked void param_null(void)
{
	asm volatile (
		"r1 = 0;"
		"call %[bpf_test_inline_kfunc2];"
		"exit;"
		:
		: __imm(bpf_test_inline_kfunc2)
		: __clobber_all
	);
}

SEC("socket")
__xlated("0: r1 = r10")
__xlated("1: r1 += -8")
__xlated("2: r2 = 8")
__xlated("3: r1 = *(u64 *)(r1 +0)")
__xlated("4: *(u64 *)(r1 +0) = 42")
__xlated("5: r0 = 0")
__xlated("6: goto pc+0")
__xlated("7: exit")
__success
__naked void param_kernel_value(void)
{
	asm volatile (
		"r1 = r10;"
		"r1 += -8;"
		"r2 = 8;"
		"call %[bpf_test_inline_kfunc3];"
		"exit;"
		:
		: __imm(bpf_test_inline_kfunc3)
		: __clobber_all
	);
}

SEC("socket")
__xlated("0: *(u64 *)(r10 -128) = r1")
__xlated("1: *(u64 *)(r10 -136) = r6")
__xlated("2: *(u64 *)(r10 -144) = r7")
__xlated("3: r0 = 0")
__xlated("4: r1 = 1")
__xlated("5: r2 = 2")
__xlated("6: r6 = 3")
__xlated("7: r7 = 4")
__xlated("8: goto pc+0")
__xlated("9: r7 = *(u64 *)(r10 -144)")
__xlated("10: r6 = *(u64 *)(r10 -136)")
__xlated("11: r1 = *(u64 *)(r10 -128)")
__xlated("12: exit")
__success
__naked void clobbered_regs(void)
{
	asm volatile (
		"*(u64 *)(r10 - 128) = r1;"
		"call %[bpf_test_inline_kfunc4];"
		"r1 = *(u64 *)(r10 - 128);"
		"exit;"
		:
		: __imm(bpf_test_inline_kfunc4)
		: __clobber_all
	);
}

SEC("socket")
__xlated("0: *(u64 *)(r10 -32) = r1")
__xlated("1: *(u64 *)(r10 -40) = r6")
__xlated("2: r0 = 0")
__xlated("3: *(u64 *)(r10 -48) = r0")
__xlated("4: r0 = *(u64 *)(r10 -48)")
__xlated("5: r6 = 1")
__xlated("6: goto pc+0")
__xlated("7: r6 = *(u64 *)(r10 -40)")
__xlated("8: r1 = *(u64 *)(r10 -32)")
__xlated("9: exit")
__success
__naked void clobbered_regs_and_stack(void)
{
	asm volatile (
		"*(u64 *)(r10 - 32) = r1;"
		"call %[bpf_test_inline_kfunc6];"
		"r1 = *(u64 *)(r10 - 32);"
		"exit;"
		:
		: __imm(bpf_test_inline_kfunc6)
		: __clobber_all
	);
}

SEC("socket")
__xlated("0: call kernel-function")
__xlated("1: exit")
__success
__naked void r10_escapes1(void)
{
	asm volatile (
		"call %[bpf_test_inline_kfunc7];"
		"exit;"
		:
		: __imm(bpf_test_inline_kfunc7)
		: __clobber_all
	);
}

SEC("socket")
__xlated("0: call kernel-function")
__xlated("1: exit")
__success
__naked void r10_escapes2(void)
{
	asm volatile (
		"call %[bpf_test_inline_kfunc8];"
		"exit;"
		:
		: __imm(bpf_test_inline_kfunc8)
		: __clobber_all
	);
}

SEC("xdp")
__xlated("5: r1 = r10")
__xlated("6: r1 += -16")
__xlated("7: r1 = *(u32 *)(r1 +8)")
__xlated("8: r1 &= ")
__xlated("9: r1 >>= ")
__xlated("10: r0 = 2")
__xlated("11: goto pc+0")
__xlated("12: exit")
__success
__naked void param_dynptr1(void)
{
	asm volatile (
		"r1 = r1;"
		"r2 = 0;"
		"r3 = r10;"
		"r3 += -16;"
		"call %[bpf_dynptr_from_xdp];"
		"r1 = r10;"
		"r1 += -16;"
		"call %[bpf_test_inline_kfunc5];"
		"exit;"
		:
		: __imm(bpf_test_inline_kfunc5),
		  __imm(bpf_dynptr_from_xdp)
		: __clobber_all
	);
}

SEC("cgroup_skb/egress")
__xlated("5: r1 = r10")
__xlated("6: r1 += -16")
__xlated("7: r1 = *(u32 *)(r1 +8)")
__xlated("8: r1 &= ")
__xlated("9: r1 >>= ")
__xlated("10: r0 = 1")
__xlated("11: goto pc+0")
__xlated("12: r0 &= 3")
__xlated("13: exit")
__success
__naked void param_dynptr2(void)
{
	asm volatile (
		"r1 = r1;"
		"r2 = 0;"
		"r3 = r10;"
		"r3 += -16;"
		"call %[bpf_dynptr_from_skb];"
		"r1 = r10;"
		"r1 += -16;"
		"call %[bpf_test_inline_kfunc5];"
		"r0 &= 3;"
		"exit;"
		:
		: __imm(bpf_test_inline_kfunc5),
		  __imm(bpf_dynptr_from_skb)
		: __clobber_all
	);
}

void __kfunc_btf_root(void)
{
	bpf_test_inline_kfunc1(0);
	bpf_test_inline_kfunc2(0);
	bpf_test_inline_kfunc3(0, 0);
	bpf_test_inline_kfunc4();
	bpf_test_inline_kfunc5(0);
	bpf_test_inline_kfunc6();
	bpf_test_inline_kfunc7();
	bpf_test_inline_kfunc8();
	bpf_dynptr_from_skb(0, 0, 0);
	bpf_dynptr_from_xdp(0, 0, 0);
}

char _license[] SEC("license") = "GPL";
