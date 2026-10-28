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

struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 4096);
} user_ringbuf SEC(".maps");

/* How many times the callback ran */
__u64 runs;

/* Unwinds on every sample */
__naked __noinline __used
static unsigned long cb_unwinds(void)
{
	asm volatile (
		"r1 = %[runs] ll;"
		"r2 = *(u64 *)(r1 + 0);"
		"r2 += 1;"
		"*(u64 *)(r1 + 0) = r2;"
		"r0 = 5;"
		unwind_exit
		:
		: __imm_addr(runs),
		  __imm_unwind_exit
	);
}

/* The pad returns the number of runs plus what the helper left in r0, 5, plus 41 */
SEC("tc")
__naked int drain(void)
{
	asm volatile (
		"r1 = %[user_ringbuf] ll;"
		"r2 = %[cb_unwinds];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_user_ringbuf_drain];"
		unwind_goto(1)
		"exit;"
		"r1 = %[runs] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"r0 += r1;"
		"r0 += 41;"
		"exit;"
		:
		: __imm_addr(user_ringbuf),
		  __imm_ptr(cb_unwinds),
		  __imm_addr(runs),
		  __imm(bpf_user_ringbuf_drain),
		  __imm_unwind_goto(1)
		: __clobber_common
	);
}

char _license[] SEC("license") = "GPL";
