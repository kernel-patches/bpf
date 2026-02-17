// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 CrowdStrike, Inc. */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

__u32 fentry_called = 0;
__u32 fexit_called = 0;
__u64 fentry_pptr = 0;
__u64 fexit_retval = 0;

typedef void **volatile *const ppvpc_t;

SEC("fentry/bpf_fentry_test14_ppptr")
int BPF_PROG(test_fentry_void_ppptr, ppvpc_t ppptr)
{
	fentry_called = 1;
	/* Invalid memory access is fixed by boundaries check or exception handler */
	fentry_pptr = (unsigned long)*ppptr;
	return 0;
}

SEC("fexit/bpf_fentry_test14_ppptr")
int BPF_PROG(test_fexit_void_ppptr, ppvpc_t ppptr, void ***ret)
{
	fexit_called = 1;
	fexit_retval = ret ? (__u64)ret : 0;
	return 0;
}
