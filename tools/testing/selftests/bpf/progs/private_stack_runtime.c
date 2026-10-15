// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../test_kmods/bpf_testmod.h"
#include "../private_stack_runtime.h"
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

const volatile __u32 target_tgid;
const volatile long seed = 1;

struct private_stack_result private_result, kernel_result;
int zero_calls;

#ifdef __BPF_FEATURE_STACK_ARGUMENT
const volatile bool has_stack_args = true;

struct frame {
	long slots[16];
};

static __noinline long check_args(long a, long b, long c, long d, long e,
				  long f, long g, long h, long i,
				  struct frame *caller)
{
	volatile long local[16] = {};
	long sum;

	local[0] = a;
	local[15] = i;
	sum = a + 2 * b + 3 * c + 4 * d + 5 * e + 6 * f + 7 * g + 8 * h + 9 * i;
	caller->slots[15] = caller->slots[0] + sum + local[0] + local[15];
	return caller->slots[15] + (bpf_get_current_pid_tgid() >> 32);
}

static __always_inline void run_args(struct private_stack_result *result)
{
	struct frame caller = {};
	long n = seed;

	caller.slots[0] = 29;
	result->value = check_args(n, n + 1, n + 2, n + 3, n + 4,
				   n + 5, n + 6, n + 7, n + 8, &caller);
	result->first = caller.slots[0];
	result->last = caller.slots[15];
	result->cpu = bpf_get_smp_processor_id();
}
#else
const volatile bool has_stack_args = false;

static __always_inline void run_args(struct private_stack_result *result)
{
}
#endif

SEC("raw_tp/sys_enter")
#ifdef __BPF_FEATURE_STACK_ARGUMENT
__arch_riscv64
/*
 * func #0, the caller. With a private stack the kernel frame holds only the
 * saved registers and the outgoing stack argument area, so it is 48 bytes =
 * 32 (ra, fp, s5, tcc) + 16 (two 8 byte outgoing slots). The 128 byte BPF
 * stack is not in this frame; it lives on the per-CPU private stack reached
 * through s5. The caller writes the two outgoing arguments relative to sp.
 */
__jited("	addi	sp, sp, -0x30")
__jited("...")
__jited("	sd	{{.*}}, 0x0(sp)")
__jited("...")
__jited("	sd	{{.*}}, 0x8(sp)")
__jited("...")
/*
 * func #1, the ten argument callee, gets a private stack of its own, so its
 * kernel frame is the 64 bytes of saved registers and nothing else. It reads
 * the two incoming stack arguments relative to fp (s0), which its prologue
 * set to the caller's sp, i.e. exactly the area the caller wrote above.
 */
__jited("func #1")
__jited("...")
__jited("	addi	sp, sp, -0x40")
__jited("...")
__jited("	ld	{{.*}}, 0x0(s0)")
__jited("...")
__jited("	ld	{{.*}}, 0x8(s0)")
#endif

int private_args(void *ctx)
{
	if ((bpf_get_current_pid_tgid() >> 32) == target_tgid)
		run_args(&private_result);
	return 0;
}

SEC("tc")
#ifdef __BPF_FEATURE_STACK_ARGUMENT
__arch_riscv64
/*
 * func #0, the caller, control group. BPF_PROG_TYPE_SCHED_CLS is
 * NO_PRIV_STACK, so the 128 byte BPF stack stays in the kernel frame and s5
 * is sp relative: 176 bytes = 32 saved + 128 BPF stack + 16 outgoing, i.e.
 * 128 bytes larger than the private stack caller above. The outgoing stack
 * argument area is written relative to sp in both cases.
 */
__jited("	addi	sp, sp, -0xb0")
__jited("...")
__jited("	addi	s5, sp, 0x90")
__jited("...")
__jited("	sd	{{.*}}, 0x0(sp)")
__jited("...")
__jited("	sd	{{.*}}, 0x8(sp)")
__jited("...")
/* func #1, the callee: 208 bytes = 64 saved + 144 BPF stack. */
__jited("func #1")
__jited("...")
__jited("	addi	sp, sp, -0xd0")
__jited("...")
__jited("	ld	{{.*}}, 0x0(s0)")
__jited("...")
__jited("	ld	{{.*}}, 0x8(s0)")
#endif

int kernel_args(struct __sk_buff *skb)
{
	run_args(&kernel_result);
	return 0;
}

SEC("struct_ops")
int BPF_PROG(zero_stack)
{
	zero_calls++;
	return 0;
}

SEC(".struct_ops")
struct bpf_testmod_ops3 zero_stack_ops = {
	.test_1 = (void *)zero_stack,
};
