// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 */

#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct bpf_dynptr {
	__u64 :64;
	__u64 :64;
} __attribute__((aligned(8)));

extern int bpf_verify_pkcs7_signature(struct bpf_dynptr *data_ptr,
				      struct bpf_dynptr *sig_ptr,
				      struct bpf_key *trusted_keyring) __ksym;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
} ringbuf SEC(".maps");

char _license[] SEC("license") = "GPL";

SEC("?lsm.s/bpf")
int BPF_PROG(dynptr_type_not_supp, int cmd, union bpf_attr *attr,
	     unsigned int size)
{
	char write_data[64] = "hello there, world!!";
	struct bpf_dynptr ptr;

	bpf_ringbuf_reserve_dynptr(&ringbuf, sizeof(write_data), 0, &ptr);

	return bpf_verify_pkcs7_signature(&ptr, &ptr, NULL);
}

SEC("?lsm.s/bpf")
int BPF_PROG(not_valid_dynptr, int cmd, union bpf_attr *attr, unsigned int size)
{
	unsigned long val;

	return bpf_verify_pkcs7_signature((struct bpf_dynptr *)&val,
					  (struct bpf_dynptr *)&val, NULL);
}

SEC("?lsm.s/bpf")
int BPF_PROG(not_ptr_to_stack, int cmd, union bpf_attr *attr, unsigned int size)
{
	unsigned long val;

	return bpf_verify_pkcs7_signature((struct bpf_dynptr *)val,
					  (struct bpf_dynptr *)val, NULL);
}
