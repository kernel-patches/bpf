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

#define FILE_PATH_SIZE 64

struct file_path_str {
	unsigned int len;
	char raw[FILE_PATH_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct file_path_str);
} array SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_QP_TRIE);
	__uint(max_entries, 1);
	__type(key, struct file_path_str);
	__type(value, __u32);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} trie SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__uint(key_size, FILE_PATH_SIZE);
	__uint(value_size, sizeof(__u32));
} htab SEC(".maps");

int pid = 0;
unsigned int trie_value = 0;
unsigned int htab_value = 0;

SEC("fentry/filp_close")
int BPF_PROG(filp_close, struct file *filp)
{
	struct path *p = &filp->f_path;
	struct file_path_str *str;
	unsigned int *value;
	int idx, len;

	if (bpf_get_current_pid_tgid() >> 32 != pid)
		return 0;

	idx = 0;
	str = bpf_map_lookup_elem(&array, &idx);
	if (!str)
		return 0;

	len = bpf_d_path(p, str->raw, sizeof(str->raw));
	if (len < 0 || len > sizeof(str->raw))
		return 0;

	str->len = len;
	value = bpf_map_lookup_elem(&trie, str);
	if (value)
		trie_value = *value;
	else
		trie_value = -1;

	value = bpf_map_lookup_elem(&htab, str->raw);
	if (value)
		htab_value = *value;
	else
		htab_value = -1;

	return 0;
}
