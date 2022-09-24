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
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(map_extra, FILE_PATH_SIZE);
} trie SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__uint(key_size, FILE_PATH_SIZE);
	__uint(value_size, 4);
} htab SEC(".maps");

int pid = 0;

unsigned int key_size;
unsigned int lookup_str_value;
unsigned int lookup_bytes_value;
unsigned int delete_again_err;

unsigned int zero_size_err;
unsigned int null_data_err;

unsigned int trie_path_value = 0;
unsigned int htab_path_value = 0;

SEC("?tp/syscalls/sys_enter_nanosleep")
int BPF_PROG(basic_ops)
{
	struct bpf_dynptr str_ptr, bytes_ptr, zero_ptr;
	unsigned int new_value, byte_size;
	unsigned int *value;
	char *raw;
	int idx;

	if (bpf_get_current_pid_tgid() >> 32 != pid)
		return 0;

	idx = 0;
	raw = bpf_map_lookup_elem(&array, &idx);
	if (!raw)
		return 0;

	byte_size = key_size;
	if (!byte_size || byte_size >= FILE_PATH_SIZE)
		return 0;

	/* Append a zero byte to make it as a string */
	bpf_dynptr_from_mem(raw, byte_size + 1, 0, &str_ptr);
	value = bpf_map_lookup_elem(&trie, &str_ptr);
	if (value)
		lookup_str_value = *value;
	else
		lookup_str_value = -1;

	/* Lookup map */
	bpf_dynptr_from_mem(raw, byte_size, 0, &bytes_ptr);
	value = bpf_map_lookup_elem(&trie, &bytes_ptr);
	if (value)
		lookup_bytes_value = *value;
	else
		lookup_bytes_value = -1;

	/* Update map and check it in userspace */
	new_value = lookup_bytes_value + 1;
	bpf_map_update_elem(&trie, &bytes_ptr, &new_value, BPF_EXIST);

	/* Delete map and check it in userspace */
	idx = 1;
	raw = bpf_map_lookup_elem(&array, &idx);
	if (!raw)
		return 0;
	bpf_dynptr_from_mem(raw, byte_size, 0, &zero_ptr);
	bpf_map_delete_elem(&trie, &zero_ptr);
	delete_again_err = bpf_map_delete_elem(&trie, &zero_ptr);

	return 0;
}

SEC("?tp/syscalls/sys_enter_nanosleep")
int BPF_PROG(zero_size_dynptr)
{
	struct bpf_dynptr ptr, bad_ptr;
	unsigned int new_value;
	void *value;
	int idx, err;
	char *raw;

	if (bpf_get_current_pid_tgid() >> 32 != pid)
		return 0;

	idx = 0;
	raw = bpf_map_lookup_elem(&array, &idx);
	if (!raw)
		return 0;

	/* Use zero-sized bpf_dynptr */
	bpf_dynptr_from_mem(raw, 0, 0, &ptr);

	value = bpf_map_lookup_elem(&trie, &ptr);
	if (value)
		zero_size_err |= 1;
	new_value = 0;
	err = bpf_map_update_elem(&trie, &ptr, &new_value, BPF_ANY);
	if (err != -EINVAL)
		zero_size_err |= 2;
	err = bpf_map_delete_elem(&trie, &ptr);
	if (err != -EINVAL)
		zero_size_err |= 4;

	/* A bad dynptr also is zero-sized */
	bpf_dynptr_from_mem(raw, 1, 1U << 31, &bad_ptr);

	value = bpf_map_lookup_elem(&trie, &bad_ptr);
	if (value)
		zero_size_err |= 8;
	new_value = 0;
	err = bpf_map_update_elem(&trie, &bad_ptr, &new_value, BPF_ANY);
	if (err != -EINVAL)
		zero_size_err |= 16;
	err = bpf_map_delete_elem(&trie, &bad_ptr);
	if (err != -EINVAL)
		zero_size_err |= 32;
	return 0;
}

SEC("?fentry/filp_close")
int BPF_PROG(d_path_key, struct file *filp)
{
	struct bpf_dynptr ptr;
	unsigned int *value;
	struct path *p;
	int idx, err;
	long len;
	char *raw;

	if (bpf_get_current_pid_tgid() >> 32 != pid)
		return 0;

	idx = 0;
	raw = bpf_map_lookup_elem(&array, &idx);
	if (!raw)
		return 0;

	p = &filp->f_path;
	len = bpf_d_path(p, raw, FILE_PATH_SIZE);
	if (len < 1 || len > FILE_PATH_SIZE)
		return 0;

	/* Include the trailing zero byte */
	bpf_dynptr_from_mem(raw, len, 0, &ptr);
	value = bpf_map_lookup_elem(&trie, &ptr);
	if (value)
		trie_path_value = *value;
	else
		trie_path_value = -1;

	/* Due to the implementation of bpf_d_path(), there will be "garbage"
	 * characters instead of zero bytes after raw[len-1], so the lookup
	 * will fail.
	 */
	value = bpf_map_lookup_elem(&htab, raw);
	if (value)
		htab_path_value = *value;
	else
		htab_path_value = -1;

	return 0;
}
