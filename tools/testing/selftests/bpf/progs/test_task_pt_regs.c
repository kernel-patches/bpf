// SPDX-License-Identifier: GPL-2.0

#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_pt_regs_helpers.h"

struct bpf_pt_regs current_regs = {};
struct bpf_pt_regs ctx_regs = {};
int uprobe_res = 0;

SEC("uprobe/trigger_func")
int handle_uprobe(struct pt_regs *ctx)
{
	struct task_struct *current;
	struct pt_regs *regs;

	current = bpf_get_current_task_btf();
	regs = (struct pt_regs *) bpf_task_pt_regs(current);
	bpf_copy_pt_regs(&current_regs, regs);
	bpf_copy_pt_regs(&ctx_regs, ctx);

	/* Prove that uprobe was run */
	uprobe_res = 1;

	return 0;
}

char _license[] SEC("license") = "GPL";
