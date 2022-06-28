// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 */

#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_DATA_SIZE (1024 * 1024)
#define MAX_SIG_SIZE 1024

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

u32 monitored_pid;
u32 trusted_keyring_serial;
unsigned long trusted_keyring_id;

struct data {
	u8 data[MAX_DATA_SIZE];
	u32 data_len;
	u8 sig[MAX_SIG_SIZE];
	u32 sig_len;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct data);
} data_input SEC(".maps");

char _license[] SEC("license") = "GPL";

SEC("lsm.s/bpf")
int BPF_PROG(bpf, int cmd, union bpf_attr *attr, unsigned int size)
{
	struct bpf_dynptr data_ptr, sig_ptr;
	struct data *data_val;
	u32 pid;
	u64 value;
	int ret, zero = 0;

	pid = bpf_get_current_pid_tgid() >> 32;
	if (pid != monitored_pid)
		return 0;

	data_val = bpf_map_lookup_elem(&data_input, &zero);
	if (!data_val)
		return 0;

	bpf_probe_read(&value, sizeof(value), &attr->value);

	bpf_copy_from_user(data_val, sizeof(struct data),
			   (void *)(unsigned long)value);

	if (data_val->data_len > sizeof(data_val->data))
		return -EINVAL;

	bpf_dynptr_from_mem(data_val->data, data_val->data_len, 0, &data_ptr);

	if (data_val->sig_len > sizeof(data_val->sig))
		return -EINVAL;

	bpf_dynptr_from_mem(data_val->sig, data_val->sig_len, 0, &sig_ptr);

	return bpf_verify_pkcs7_signature(&data_ptr, &sig_ptr,
					  trusted_keyring_serial, 0,
					  trusted_keyring_id);
}
