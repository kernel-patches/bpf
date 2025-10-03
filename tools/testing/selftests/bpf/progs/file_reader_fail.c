// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <string.h>
#include <stdbool.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

int err;
void *user_ptr;

char buf[256];

static long process_vma_unreleased_ref(struct task_struct *task, struct vm_area_struct *vma,
				       void *data)
{
	struct bpf_dynptr dynptr;

	if (!vma->vm_file)
		return 1;

	err = bpf_dynptr_from_file(vma->vm_file, 0, &dynptr);
	return err ? 1 : 0;
}

SEC("fentry.s/" SYS_PREFIX "sys_nanosleep")
__failure __msg("Unreleased reference id=") int on_nanosleep_unreleased_ref(void *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();

	bpf_find_vma(task, (unsigned long)user_ptr, process_vma_unreleased_ref, NULL, 0);
	return 0;
}

SEC("xdp")
__failure __msg("Expected a dynptr of type file as arg #0")
int xdp_wrong_dynptr_type(struct xdp_md *xdp)
{
	struct bpf_dynptr dynptr;

	bpf_dynptr_from_xdp(xdp, 0, &dynptr);
	bpf_dynptr_file_discard(&dynptr);
	return 0;
}

SEC("xdp")
__failure __msg("Expected an initialized dynptr as arg #0")
int xdp_no_dynptr_type(struct xdp_md *xdp)
{
	struct bpf_dynptr dynptr;

	bpf_dynptr_file_discard(&dynptr);
	return 0;
}
