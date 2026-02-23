// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 CrowdStrike, Inc. */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

struct bpf_fentry_test_pptr_t {
	__u32 value1;
	__u32 value2;
};

/*
 * Workaround for a bug in LLVM:
 * fatal error: error in backend: Empty type name for BTF_TYPE_ID_REMOTE reloc
 */
typedef struct bpf_fentry_test_pptr_t *bpf_fentry_test_pptr_p;

__u32 fentry_called = 0;
__u32 fentry_ptr_field_value1 = 0;
__u32 fentry_ptr_field_value2 = 0;
__u32 fexit_called = 0;
__u32 fexit_ptr_field_value1 = 0;
__u32 fexit_ptr_field_value2 = 0;
__u32 fexit_retval = 0;

SEC("fentry/bpf_fentry_test11_pptr_nullable")
int BPF_PROG(test_fentry_pptr_nullable, struct bpf_fentry_test_pptr_t **pptr__nullable)
{
	struct bpf_fentry_test_pptr_t *ptr;

	fentry_called = 1;
	/* For scalars, the verifier does not enforce NULL pointer checks. */
	ptr = *bpf_core_cast(pptr__nullable, bpf_fentry_test_pptr_p);
	bpf_probe_read_kernel(&fentry_ptr_field_value1, sizeof(fentry_ptr_field_value1), &ptr->value1);
	bpf_probe_read_kernel(&fentry_ptr_field_value2, sizeof(fentry_ptr_field_value2), &ptr->value2);
	return 0;
}

SEC("fexit/bpf_fentry_test11_pptr_nullable")
int BPF_PROG(test_fexit_pptr_nullable, struct bpf_fentry_test_pptr_t **pptr__nullable, int ret)
{
	struct bpf_fentry_test_pptr_t **pptr;
	struct bpf_fentry_test_pptr_t *ptr;

	fexit_called = 1;
	fexit_retval = ret;
	/* For scalars, the verifier does not enforce NULL pointer checks. */
	pptr = bpf_core_cast(pptr__nullable, bpf_fentry_test_pptr_p);
	ptr = bpf_core_cast((*pptr), struct bpf_fentry_test_pptr_t);
	fexit_ptr_field_value1 = ptr->value1;
	fexit_ptr_field_value2 = ptr->value2;
	return 0;
}
