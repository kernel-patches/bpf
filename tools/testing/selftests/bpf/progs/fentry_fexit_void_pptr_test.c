// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 CrowdStrike, Inc. */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

#define TELEMETRY_COUNT 3

struct {
	__u32 fentry_called;
	__u32 fexit_called;
	__u32 fentry_pptr_addr_valid;
	__u32 fexit_pptr_addr_valid;
	__u64 fentry_pptr;
	__u64 fentry_ptr;
	__u64 fexit_pptr;
	__u64 fexit_ptr;
} telemetry[TELEMETRY_COUNT];

volatile unsigned int current_index = 0;

/*
 * Workaround for a bug in LLVM:
 * fatal error: error in backend: Empty type name for BTF_TYPE_ID_REMOTE reloc
 */
typedef void *void_p;

SEC("fentry/bpf_fentry_test13_pptr")
int BPF_PROG(test_fentry_void_pptr, void **pptr)
{
	void *ptr;
	unsigned int i = current_index;

	if (i >= TELEMETRY_COUNT)
		return 0;

	telemetry[i].fentry_pptr_addr_valid =
		(bpf_probe_read_kernel(&ptr, sizeof(ptr), pptr) == 0);
	if (!telemetry[i].fentry_pptr_addr_valid)
		ptr = NULL;

	telemetry[i].fentry_called = 1;
	telemetry[i].fentry_pptr = (__u64)pptr;
	telemetry[i].fentry_ptr = (__u64)ptr;
	return 0;
}

SEC("fexit/bpf_fentry_test13_pptr")
int BPF_PROG(test_fexit_void_pptr, void **pptr, __u8 ret)
{
	unsigned int i = current_index;

	if (i >= TELEMETRY_COUNT)
		return 0;

	telemetry[i].fexit_called = 1;
	telemetry[i].fexit_pptr = (__u64)pptr;
	telemetry[i].fexit_pptr_addr_valid = ret;

	/*
	 * For invalid addresses, the destination register for *dptr is set
	 * to 0 by the BPF exception handler, JIT address range check, or
	 * the BPF interpreter.
	 */
	telemetry[i].fexit_ptr = (__u64)*bpf_core_cast(pptr, void_p);
	current_index = i + 1;
	return 0;
}
