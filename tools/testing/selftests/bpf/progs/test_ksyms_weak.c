// SPDX-License-Identifier: GPL-2.0
/*
 * Test weak ksyms.
 *
 * Copyright (c) 2021 Google
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

int out__existing_typed = -1;
__u64 out__existing_typeless = -1;

__u64 out__non_existing_typeless = -1;
__u64 out__non_existing_typed = -1;

/* existing weak symbols */

/* test existing weak symbols can be resolved. */
extern const struct rq runqueues __ksym __weak; /* typed */
extern const void bpf_prog_active __ksym __weak; /* typeless */


/* non-existing weak symbols. */

/* typeless symbols, default to zero. */
extern const void bpf_link_fops1 __ksym __weak;

/* typed symbols, fail verifier checks if referenced. */
extern const int bpf_link_fops2 __ksym __weak;

/* typed symbols, pass if not referenced. */
extern const int bpf_link_fops3 __ksym __weak;

SEC("raw_tp/sys_enter")
int pass_handler(const void *ctx)
{
	/* tests existing symbols. */
	struct rq *rq = (struct rq *)bpf_per_cpu_ptr(&runqueues, 0);
	if (rq)
		out__existing_typed = rq->cpu;
	out__existing_typeless = (__u64)&bpf_prog_active;

	/* tests non-existing symbols. */
	out__non_existing_typeless = (__u64)&bpf_link_fops1;

	return 0;
}

SEC("raw_tp/sys_exit")
int fail_handler(const void *ctx)
{
	/* tests non-existing symbols. */
	out__non_existing_typed = (__u64)&bpf_link_fops2;

	return 0;
}

char _license[] SEC("license") = "GPL";
