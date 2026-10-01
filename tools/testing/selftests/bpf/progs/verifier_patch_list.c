// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "../../../include/linux/filter.h"
#include "bpf_misc.h"

/*
 * bpf_do_misc_fixups() guards each division by a register against division
 * by zero with a 4 insn patch. Jumps to a patched insn must land on the
 * first insn of its patch, other jumps must follow the insns they target.
 */

SEC("raw_tp")
__description("patch list: forward jumps to and over patched insns")
__arch_x86_64
__arch_arm64
__success
__xlated("0: call")
__xlated("1: r1 = r0")
__xlated("2: r0 = 7")
__xlated("3: if r1 > 0x5 goto pc+1")
__xlated("4: r0 = 9")
__xlated("5: if r1 != 0x0 goto pc+2")
__xlated("6: w0 ^= w0")
__xlated("7: goto pc+1")
__xlated("8: r0 /= r1")
__xlated("9: if r0 > 0x3 goto pc+4")
__xlated("10: if r1 != 0x0 goto pc+2")
__xlated("11: w0 ^= w0")
__xlated("12: goto pc+1")
__xlated("13: r0 /= r1")
__xlated("14: exit")
__naked void patch_list_forward(void)
{
	asm volatile (
	"call %[bpf_get_prandom_u32];"
	"r1 = r0;"
	"r0 = 7;"
	"if r1 > 5 goto l0_%=;"
	"r0 = 9;"
"l0_%=:"
	"r0 /= r1;"
	"if r0 > 3 goto l1_%=;"
	"r0 /= r1;"
"l1_%=:"
	"exit;"
	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("raw_tp")
__description("patch list: backward jump to a patched insn")
__arch_x86_64
__arch_arm64
__success
__xlated("0: call")
__xlated("1: r1 = r0")
__xlated("2: r2 = 0")
__xlated("3: if r1 != 0x0 goto pc+2")
__xlated("4: w0 ^= w0")
__xlated("5: goto pc+1")
__xlated("6: r0 /= r1")
__xlated("7: r2 += 1")
__xlated("8: if r2 < 0x3 goto pc-6")
__xlated("9: exit")
__naked void patch_list_backward(void)
{
	asm volatile (
	"call %[bpf_get_prandom_u32];"
	"r1 = r0;"
	"r2 = 0;"
"l0_%=:"
	"r0 /= r1;"
	"r2 += 1;"
	"if r2 < 3 goto l0_%=;"
	"exit;"
	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/* The jump of may_goto leaves its own patch and crosses another one. */
SEC("raw_tp")
__description("patch list: may_goto between patched insns")
__arch_x86_64
__success
__xlated("0: *(u64 *)(r10 -16) = 65535")
__xlated("1: *(u64 *)(r10 -8) = 0")
__xlated("2: call")
__xlated("3: r1 = r0")
__xlated("4: if r1 != 0x0 goto pc+2")
__xlated("5: w0 ^= w0")
__xlated("6: goto pc+1")
__xlated("7: r0 /= r1")
__xlated("8: r12 = *(u64 *)(r10 -16)")
__xlated("9: if r12 == 0x0 goto pc+9")
__xlated("...")
__xlated("15: if r1 != 0x0 goto pc+2")
__xlated("16: w0 ^= w0")
__xlated("17: goto pc+1")
__xlated("18: r0 /= r1")
__xlated("19: exit")
__naked void patch_list_may_goto(void)
{
	asm volatile (
	"call %[bpf_get_prandom_u32];"
	"r1 = r0;"
	"r0 /= r1;"
	".8byte %[may_goto];"
	"r0 /= r1;"
	"exit;"
	:
	: __imm(bpf_get_prandom_u32),
	  __imm_insn(may_goto, BPF_RAW_INSN(BPF_JMP | BPF_JCOND, 0, 0, 1 /* offset */, 0))
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
