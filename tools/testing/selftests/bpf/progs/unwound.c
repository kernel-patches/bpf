// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "../../../include/linux/filter.h"
#include "bpf_misc.h"

#define unwind_goto(off) ".8byte %[insn_unwind_goto_" #off "];"
#define unwind_exit ".8byte %[insn_unwind_exit];"

#define __imm_unwind_goto(off) \
	__imm_insn(insn_unwind_goto_##off, \
		   BPF_RAW_INSN(BPF_JMP | BPF_JCOND, 0, BPF_UNWIND_GOTO, off, 0))
#define __imm_unwind_exit \
	__imm_insn(insn_unwind_exit, \
		   BPF_RAW_INSN(BPF_JMP | BPF_EXIT, 0, BPF_UNWIND_EXIT, 0, 0))

unsigned long one = 1;

__naked __noinline __used
static unsigned long unwinds(void)
{
	asm volatile (
		"r0 = 0;"
		unwind_exit
		:
		: __imm_unwind_exit
	);
}

SEC("socket")
__naked void caught(void)
{
	asm volatile (
		"call unwinds;"
		unwind_goto(1)
		"exit;"
		"r0 = 42;"
		"exit;"
		:
		: __imm_unwind_goto(1)
		: __clobber_all
	);
}

SEC("socket")
__naked void not_caught(void)
{
	asm volatile (
		"call unwinds;"
		unwind_goto(1)
		"exit;"
		"r0 = 7;"
		unwind_exit
		:
		: __imm_unwind_goto(1),
		  __imm_unwind_exit
		: __clobber_all
	);
}

SEC("socket")
__naked void spins(void)
{
	asm volatile (
		"r6 = %[one] ll;"
	"1:"
		"r1 = *(u64 *)(r6 + 0);"
		"if r1 != 0 goto 1b;"
		"r0 = 1;"
		"exit;"
		:
		: __imm_addr(one)
		: __clobber_all
	);
}

__naked __noinline __used
static unsigned long calls_itself(void)
{
	asm volatile (
		"r1 += 1;"
		"call calls_itself;"
		"exit;"
		::: __clobber_all
	);
}

SEC("socket")
__naked void too_deep(void)
{
	asm volatile (
		"r1 = 0;"
		"call calls_itself;"
		"r0 = 3;"
		"exit;"
		::: __clobber_all
	);
}

/* the test attaches them to calls_itself() */
SEC("?fentry")
int on_entry(void *ctx)
{
	return 0;
}

SEC("?fexit")
int on_exit(void *ctx)
{
	return 0;
}

char _license[] SEC("license") = "GPL";
