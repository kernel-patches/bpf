// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022, Oracle and/or its affiliates. */

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

int uprobe_byname_parm1 = 0;
int uprobe_byname_res = 0;
int uretprobe_byname_rc = 0;
int uretprobe_byname_res = 0;
size_t uprobe_byname2_parm1 = 0;
int uprobe_byname2_res = 0;
int uretprobe_byname2_rc = 0;
pid_t uretprobe_byname2_res = 0;

/* This program cannot auto-attach, but that should not stop other
 * programs from attaching.
 */
SEC("uprobe")
int handle_uprobe_noautoattach(struct pt_regs *ctx)
{
	return 0;
}

SEC("uprobe//proc/self/exe:autoattach_trigger_func")
int handle_uprobe_byname(struct pt_regs *ctx)
{
	if (PT_REGS_PARM1_CORE(ctx) == uprobe_byname_parm1)
		uprobe_byname_res = 1;
	return 0;
}

SEC("uretprobe//proc/self/exe:autoattach_trigger_func")
int handle_uretprobe_byname(struct pt_regs *ctx)
{
	if (PT_REGS_RC_CORE(ctx) == uretprobe_byname_rc)
		uretprobe_byname_res = 2;
	return 0;
}


SEC("uprobe/libc.so.6:malloc")
int handle_uprobe_byname2(struct pt_regs *ctx)
{
	if (PT_REGS_PARM1_CORE(ctx) == uprobe_byname2_parm1)
		uprobe_byname2_res = 3;
	return 0;
}

SEC("uretprobe/libc.so.6:getpid")
int handle_uretprobe_byname2(struct pt_regs *ctx)
{
	if (PT_REGS_RC_CORE(ctx) == uretprobe_byname2_rc)
		uretprobe_byname2_res = 4;
	return 0;
}

char _license[] SEC("license") = "GPL";
