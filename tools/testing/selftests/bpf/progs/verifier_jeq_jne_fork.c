// SPDX-License-Identifier: GPL-2.0
/* Tests for JEQ/JNE not-equal branch forking.
 *
 * When the verifier processes JEQ/JNE with a known constant, it forks
 * the not-equal branch into two sub-states:
 *   fork1: dst > const  (unsigned, via JGT refinement)
 *   fork2: dst < const  (unsigned, via JLT refinement)
 * This gives tighter range tracking than the original JNE edge-trim,
 * which only adjusts bounds when the constant is at the range boundary.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

/* JNE with BPF_K: both forks land on the jump target and are popped
 * from the verifier stack, so both appear in the "from X to Y:" log.
 *
 * r0 in [0, 7], JNE r0, 3:
 *   fork2 (popped first, JLT): r0 in [0, 2]
 *   fork1 (popped second, JGT): r0 in [4, 7]
 */
SEC("socket")
__description("jne_k: neq branch forked into r0 > 3 and r0 < 3")
__success __log_level(2)
__msg("R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=2")
__msg("R0=scalar(smin=umin=smin32=umin32=4,smax=umax=smax32=umax32=7")
__retval(0)
__naked void jne_k_neq_fork(void)
{
	asm volatile (
	"call %[bpf_ktime_get_ns];"
	"r0 &= 7;"
	"if r0 != 3 goto l_neq_%=;"
	"r0 = 0;"
	"exit;"
	"l_neq_%=:"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_ktime_get_ns)
	: __clobber_all);
}

/* JEQ with BPF_K: fork1 is the continuation (not popped) and fork2
 * is popped.  We verify fork2's bounds in the log.
 *
 * r0 in [0, 7], JEQ r0, 3:
 *   fork1 (continuation, JGT): r0 in [4, 7]
 *   fork2 (popped, JLT):       r0 in [0, 2]
 */
SEC("socket")
__description("jeq_k: neq branch forked, fork2 has r0 < 3")
__success __log_level(2)
__msg("R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=2")
__retval(0)
__naked void jeq_k_neq_fork(void)
{
	asm volatile (
	"call %[bpf_ktime_get_ns];"
	"r0 &= 7;"
	"if r0 == 3 goto l_eq_%=;"
	"r0 = 0;"
	"exit;"
	"l_eq_%=:"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_ktime_get_ns)
	: __clobber_all);
}

/* JEQ with BPF_X: register source containing a known constant.
 *
 * r0 in [0, 7], r1 = 3, JEQ r0, r1:
 *   fork2 (popped, JLT): r0 in [0, 2]
 */
SEC("socket")
__description("jeq_x: neq branch forked with register source")
__success __log_level(2)
__msg("R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=2")
__retval(0)
__naked void jeq_x_neq_fork(void)
{
	asm volatile (
	"call %[bpf_ktime_get_ns];"
	"r0 &= 7;"
	"r1 = 3;"
	"if r0 == r1 goto l_eq_%=;"
	"r0 = 0;"
	"exit;"
	"l_eq_%=:"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_ktime_get_ns)
	: __clobber_all);
}

/* JMP32 JEQ with BPF_K: 32-bit comparison variant.
 * Fork uses u32_min/u32_max for the feasibility check.
 *
 * w0 in [0, 7], JEQ32 w0, 3:
 *   fork2 (popped, JLT32): w0 in [0, 2]
 */
SEC("socket")
__description("jeq32_k: 32-bit neq branch forked")
__success __log_level(2)
__msg("R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=2")
__retval(0)
__naked void jeq32_k_neq_fork(void)
{
	asm volatile (
	"call %[bpf_ktime_get_ns];"
	"w0 &= 7;"
	"if w0 == 3 goto l_eq_%=;"
	"r0 = 0;"
	"exit;"
	"l_eq_%=:"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_ktime_get_ns)
	: __clobber_all);
}

/* JNE with larger range and different constant.
 * r0 in [0, 255], JNE r0, 100:
 *   fork2 (JLT): r0 in [0, 99]
 *   fork1 (JGT): r0 in [101, 255]
 */
SEC("socket")
__description("jne_k: neq branch forked with wider range")
__success __log_level(2)
__msg("R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=99")
__msg("R0=scalar(smin=umin=smin32=umin32=101,smax=umax=smax32=umax32=255")
__retval(0)
__naked void jne_k_neq_fork_wide(void)
{
	asm volatile (
	"call %[bpf_ktime_get_ns];"
	"r0 &= 0xff;"
	"if r0 != 100 goto l_neq_%=;"
	"r0 = 0;"
	"exit;"
	"l_neq_%=:"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_ktime_get_ns)
	: __clobber_all);
}

/* Const at umin boundary — no fork expected.
 * r0 in [0, 7], JEQ r0, 0:
 *   Fork condition: umin(0) < 0 is false for unsigned → no fork.
 *   Edge-trim gives not-equal branch r0 in [1, 7].
 */
SEC("socket")
__description("jeq_k: const at umin, no fork needed")
__success
__retval(0)
__naked void jeq_k_no_fork_umin(void)
{
	asm volatile (
	"call %[bpf_ktime_get_ns];"
	"r0 &= 7;"
	"if r0 == 0 goto l_eq_%=;"
	"r0 = 0;"
	"exit;"
	"l_eq_%=:"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_ktime_get_ns)
	: __clobber_all);
}

/* Const at umax boundary — no fork expected.
 * r0 in [0, 7], JEQ r0, 7:
 *   Fork condition: umax(7) > 7 is false → no fork.
 *   Edge-trim gives not-equal branch r0 in [0, 6].
 */
SEC("socket")
__description("jeq_k: const at umax, no fork needed")
__success
__retval(0)
__naked void jeq_k_no_fork_umax(void)
{
	asm volatile (
	"call %[bpf_ktime_get_ns];"
	"r0 &= 7;"
	"if r0 == 7 goto l_eq_%=;"
	"r0 = 0;"
	"exit;"
	"l_eq_%=:"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_ktime_get_ns)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
