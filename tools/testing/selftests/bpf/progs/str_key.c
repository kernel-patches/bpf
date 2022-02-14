// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2022. Huawei Technologies Co., Ltd */
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct path {
} __attribute__((preserve_access_index));

struct file {
	struct path f_path;
} __attribute__((preserve_access_index));

#define HTAB_NAME_SIZE 64

struct str_htab_key {
	struct bpf_str_key_stor name;
	char raw[HTAB_NAME_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, struct str_htab_key);
	__type(value, __u32);
	__uint(map_flags, BPF_F_STR_IN_KEY);
} str_htab SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__uint(key_size, HTAB_NAME_SIZE);
	__uint(value_size, sizeof(__u32));
} byte_htab SEC(".maps");

int pid = 0;
unsigned int str_htab_value = 0;
unsigned int byte_htab_value = 0;

SEC("fentry/filp_close")
int BPF_PROG(filp_close, struct file *filp)
{
	struct path *p = &filp->f_path;
	struct str_htab_key key;
	unsigned int *value;
	int len;

	if (bpf_get_current_pid_tgid() >> 32 != pid)
		return 0;

	__builtin_memset(key.raw, 0, sizeof(key.raw));
	len = bpf_d_path(p, key.raw, sizeof(key.raw));
	if (len < 0 || len > sizeof(key.raw))
		return 0;

	key.name.hash = 0;
	key.name.len = len;
	value = bpf_map_lookup_elem(&str_htab, &key);
	if (value)
		str_htab_value = *value;
	else
		str_htab_value = -1;

	value = bpf_map_lookup_elem(&byte_htab, key.raw);
	if (value)
		byte_htab_value = *value;
	else
		byte_htab_value = -1;

	return 0;
}
