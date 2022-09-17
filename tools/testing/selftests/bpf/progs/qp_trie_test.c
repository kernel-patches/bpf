// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2022. Huawei Technologies Co., Ltd */
#include <stdbool.h>
#include <errno.h>
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

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__uint(key_size, 4);
	__uint(value_size, FILE_PATH_SIZE);
} array SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_QP_TRIE);
	__uint(max_entries, 2);
	__type(key, struct bpf_dynptr);
	__type(value, unsigned int);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_DYNPTR_KEY);
	__uint(map_extra, FILE_PATH_SIZE);
} trie SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__uint(key_size, FILE_PATH_SIZE);
	__uint(value_size, 4);
} htab SEC(".maps");

int pid = 0;
unsigned int trie_value = 0;
unsigned int htab_value = 0;
bool zero_sized_key_bad = false;

SEC("fentry/filp_close")
int BPF_PROG(filp_close, struct file *filp)
{
	struct bpf_dynptr str_ptr, zero_ptr, zero_sized_ptr;
	unsigned int new_value, *value;
	int idx, len, err;
	struct path *p;
	char *raw;

	if (bpf_get_current_pid_tgid() >> 32 != pid)
		return 0;

	idx = 0;
	raw = bpf_map_lookup_elem(&array, &idx);
	if (!raw)
		return 0;

	p = &filp->f_path;
	len = bpf_d_path(p, raw, FILE_PATH_SIZE);
	if (len < 0 || len > FILE_PATH_SIZE)
		return 0;

	bpf_dynptr_from_mem(raw, len, 0, &str_ptr);
	value = bpf_map_lookup_elem(&trie, &str_ptr);
	if (value)
		trie_value = *value;
	else
		trie_value = -1;

	value = bpf_map_lookup_elem(&htab, raw);
	if (value)
		htab_value = *value;
	else
		htab_value = -1;

	/* Update qp_trie map */
	new_value = trie_value + 1;
	bpf_map_update_elem(&trie, &str_ptr, &new_value, BPF_ANY);

	idx = 1;
	raw = bpf_map_lookup_elem(&array, &idx);
	if (!raw)
		return 0;
	bpf_dynptr_from_mem(raw, 1, 0, &zero_ptr);
	bpf_map_delete_elem(&trie, &zero_ptr);

	/* Use zero-sized bpf_dynptr */
	bpf_dynptr_from_mem(raw, 0, 0, &zero_sized_ptr);

	value = bpf_map_lookup_elem(&trie, &zero_sized_ptr);
	if (value)
		zero_sized_key_bad = true;
	err = bpf_map_update_elem(&trie, &zero_sized_ptr, &new_value, BPF_ANY);
	if (err != -EINVAL)
		zero_sized_key_bad = true;
	err = bpf_map_delete_elem(&trie, &zero_sized_ptr);
	if (err != -EINVAL)
		zero_sized_key_bad = true;

	return 0;
}
