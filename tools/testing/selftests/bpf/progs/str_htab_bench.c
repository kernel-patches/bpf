// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021. Huawei Technologies Co., Ltd */
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_STR_KEY_SIZE 4096
#define MAX_ENTRY_NR 1000

/* key_size and max_entries will be set by htab benchmark */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(value_size, sizeof(__u32));
} bytes_htab SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(value_size, sizeof(__u32));
	__uint(map_flags, BPF_F_STR_KEY);
} str_htab SEC(".maps");

char _license[] SEC("license") = "GPL";

const char keys[MAX_ENTRY_NR][MAX_STR_KEY_SIZE];

unsigned int loops = 0;
long hits = 0;
long drops = 0;

static int lookup_bytes(__u32 index, void *data)
{
	unsigned int *value;

	if (index >= MAX_ENTRY_NR)
		return 1;

	value = bpf_map_lookup_elem(&bytes_htab, keys[index]);
	if (value)
		__sync_add_and_fetch(&hits, 1);
	else
		__sync_add_and_fetch(&drops, 1);

	return 0;
}

static int lookup_str(__u32 index, void *data)
{
	unsigned int *value;

	if (index >= MAX_ENTRY_NR)
		return 1;

	value = bpf_map_lookup_elem(&str_htab, keys[index]);
	if (value)
		__sync_add_and_fetch(&hits, 1);
	else
		__sync_add_and_fetch(&drops, 1);

	return 0;
}

static int update_bytes(__u32 index, void *data)
{
	unsigned int value = 2;
	int err;

	if (index >= MAX_ENTRY_NR)
		return 1;

	err = bpf_map_update_elem(&bytes_htab, keys[index], &value, BPF_EXIST);
	if (!err)
		__sync_add_and_fetch(&hits, 1);
	else
		__sync_add_and_fetch(&drops, 1);

	return 0;
}

static int update_str(__u32 index, void *data)
{
	unsigned int value = 0;
	int err;

	if (index >= MAX_ENTRY_NR)
		return 1;

	err = bpf_map_update_elem(&str_htab, keys[index], &value, BPF_EXIST);
	if (!err)
		__sync_add_and_fetch(&hits, 1);
	else
		__sync_add_and_fetch(&drops, 1);

	return 0;
}

SEC("tp/syscalls/sys_enter_getpgid")
int htab_bytes_lookup(void *ctx)
{
	bpf_loop(loops, lookup_bytes, NULL, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_getpgid")
int htab_str_lookup(void *ctx)
{
	bpf_loop(loops, lookup_str, NULL, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_getpgid")
int htab_bytes_update(void *ctx)
{
	bpf_loop(loops, update_bytes, NULL, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_getpgid")
int htab_str_update(void *ctx)
{
	bpf_loop(loops, update_str, NULL, 0);
	return 0;
}
