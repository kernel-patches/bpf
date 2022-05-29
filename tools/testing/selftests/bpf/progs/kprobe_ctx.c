// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

volatile void *expected_p1;
volatile void *expected_p2;
volatile void *expected_p3;
volatile void *expected_p4;
volatile void *expected_p5;
volatile bool ret = false;

SEC("kprobe/this_function_does_not_exist")
int prog(struct pt_regs *ctx)
{
	void *p1, *p2, *p3, *p4, *p5;

	p1 = (void *)PT_REGS_PARM1(ctx);
	p2 = (void *)PT_REGS_PARM2(ctx);
	p3 = (void *)PT_REGS_PARM3(ctx);
	p4 = (void *)PT_REGS_PARM4(ctx);
	p5 = (void *)PT_REGS_PARM5(ctx);

	if (p1 != expected_p1 || p2 != expected_p2 || p3 != expected_p3 ||
	    p4 != expected_p4 || p5 != expected_p5)
		return 0;

	ret = true;
	return 0;
}

char _license[] SEC("license") = "GPL";
