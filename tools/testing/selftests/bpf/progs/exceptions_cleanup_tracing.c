// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/*
 * Tracing programs aimed at foo1() of progs/exceptions_cleanup.c, a subprog
 * an unwind passes through. The attach target is set at load time.
 */
SEC("?fexit")
int BPF_PROG(fexit_unwinding_subprog)
{
	return 0;
}

SEC("?fentry")
int BPF_PROG(fentry_unwinding_subprog)
{
	return 0;
}

char _license[] SEC("license") = "GPL";
