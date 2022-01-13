// SPDX-License-Identifier: GPL-2.0
/* Copyright 2022 Sony Group Corporation */
#include <linux/bpf.h>
#include <linux/ptrace.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#if defined(__TARGET_ARCH_x86)
#define SYS_PREFIX "__x64_"
#elif defined(__TARGET_ARCH_s390)
#define SYS_PREFIX "__s390x_"
#elif defined(__TARGET_ARCH_arm64)
#define SYS_PREFIX "__arm64_"
#else
#define SYS_PREFIX ""
#endif

int arg1 = 0;
unsigned long arg2 = 0;
unsigned long arg3 = 0;
unsigned long arg4_cx = 0;
unsigned long arg4 = 0;
unsigned long arg5 = 0;

SEC("kprobe/" SYS_PREFIX "sys_prctl")
int BPF_KPROBE(handle_sys_prctl)
{
	struct pt_regs *real_regs;
	int orig_arg1;
	unsigned long orig_arg2, orig_arg3, orig_arg4_cx, orig_arg4, orig_arg5;

	real_regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
	bpf_probe_read_kernel(&orig_arg1, sizeof(orig_arg1), &PT_REGS_PARM1_SYSCALL(real_regs));
	bpf_probe_read_kernel(&orig_arg2, sizeof(orig_arg2), &PT_REGS_PARM2_SYSCALL(real_regs));
	bpf_probe_read_kernel(&orig_arg3, sizeof(orig_arg3), &PT_REGS_PARM3_SYSCALL(real_regs));
	bpf_probe_read_kernel(&orig_arg4_cx, sizeof(orig_arg4_cx), &PT_REGS_PARM4(real_regs));
	bpf_probe_read_kernel(&orig_arg4, sizeof(orig_arg4), &PT_REGS_PARM4_SYSCALL(real_regs));
	bpf_probe_read_kernel(&orig_arg5, sizeof(orig_arg5), &PT_REGS_PARM5_SYSCALL(real_regs));

	/* copy all actual args and the wrong arg4 on x86_64 */
	arg1 = orig_arg1;
	arg2 = orig_arg2;
	arg3 = orig_arg3;
	arg4_cx = orig_arg4_cx;
	arg4 = orig_arg4;
	arg5 = orig_arg5;

	return 0;
}

char _license[] SEC("license") = "GPL";
