// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 CrowdStrike, Inc. */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct bpf_fentry_test_pptr_t {
	__u32 value;
};

__u32 fentry_called = 0;
__u32 fentry_ptr_field_value = 0;
__u32 fexit_called = 0;
__u32 fexit_ptr_field_value = 0;
__u32 fexit_retval = 0;

SEC("fentry/bpf_fentry_test11_pptr_nullable")
int BPF_PROG(test_fentry_pptr_nullable, struct bpf_fentry_test_pptr_t **pptr__nullable)
{
	struct bpf_fentry_test_pptr_t *ptr;

	fentry_called = 1;
	if (!pptr__nullable)
		return 0;

	ptr = *pptr__nullable;
	if (!ptr)
		return 0;

	bpf_probe_read_kernel(&fentry_ptr_field_value, sizeof(fentry_ptr_field_value), &ptr->value);
	return 0;
}

SEC("fexit/bpf_fentry_test11_pptr_nullable")
int BPF_PROG(test_fexit_pptr_nullable, struct bpf_fentry_test_pptr_t **pptr__nullable, int ret)
{
	struct bpf_fentry_test_pptr_t *ptr;

	fexit_called = 1;
	fexit_retval = ret;
	if (!pptr__nullable)
		return 0;

	ptr = *pptr__nullable;
	if (!ptr)
		return 0;

	bpf_probe_read_kernel(&fexit_ptr_field_value, sizeof(fexit_ptr_field_value), &ptr->value);
	return 0;
}
