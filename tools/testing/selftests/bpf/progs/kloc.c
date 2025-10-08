// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025, Oracle and/or its affiliates. */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/loc.bpf.h>

char _license[] SEC("license") = "GPL";

int kloc_triggered;
size_t kloc_size;
int test_pid;

/* This function is inlined to __sys_bpf() and we trigger a call to
 * it via bpf_obj_get_opts().
 */
SEC("kloc/vmlinux:copy_from_bpfptr_offset")
int BPF_KLOC(trace_copy_from_bpfptr_offset, void *dst, void *uattr, size_t offset, size_t size)
{
	int pid = bpf_get_current_pid_tgid() >> 32;
	long s;

	if (test_pid != pid)
		return 0;

	kloc_triggered++;

	/* is arg available? */
	if (bpf_loc_arg(ctx, 3, &s) == 0)
		kloc_size = size;

	return 0;
}
