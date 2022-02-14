// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2022. Huawei Technologies Co., Ltd */
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_ENTRY_NR 1000
#define DFT_STR_KEY_SIZE 252

struct htab_byte_key {
	char name[DFT_STR_KEY_SIZE];
};

struct htab_str_key {
	struct bpf_str_key_stor name;
	char raw[DFT_STR_KEY_SIZE];
};

struct htab_int_byte_key {
	int cookie;
	char name[DFT_STR_KEY_SIZE];
};

struct htab_int_str_key {
	int cookie;
	struct bpf_str_key_stor name;
	char raw[DFT_STR_KEY_SIZE];
};

struct htab_int_bytes_key {
	int cookie;
	char name[DFT_STR_KEY_SIZE / 2];
	char addr[DFT_STR_KEY_SIZE / 2];
};

struct htab_int_strs_key {
	int cookie;
	struct bpf_str_key_desc name;
	struct bpf_str_key_desc addr;
	struct bpf_str_key_stor stor;
	char raw[DFT_STR_KEY_SIZE];
};

/* max_entries will be set by htab benchmark */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct htab_byte_key);
	__uint(value_size, 4);
	__type(value, __u32);
} byte_htab SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct htab_int_byte_key);
	__type(value, __u32);
} int_byte_htab SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct htab_int_bytes_key);
	__type(value, __u32);
} int_bytes_htab SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct htab_str_key);
	__type(value, __u32);
	__uint(map_flags, BPF_F_STR_IN_KEY);
} str_htab SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct htab_int_str_key);
	__type(value, __u32);
	__uint(map_flags, BPF_F_STR_IN_KEY);
} int_str_htab SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct htab_int_strs_key);
	__type(value, __u32);
	__uint(map_flags, BPF_F_STR_IN_KEY);
} int_strs_htab SEC(".maps");

char _license[] SEC("license") = "GPL";

struct htab_byte_key byte_keys[MAX_ENTRY_NR];
struct htab_str_key str_keys[MAX_ENTRY_NR];
struct htab_int_byte_key int_byte_keys[MAX_ENTRY_NR];
struct htab_int_str_key int_str_keys[MAX_ENTRY_NR];
struct htab_int_bytes_key int_bytes_keys[MAX_ENTRY_NR];
struct htab_int_strs_key int_strs_keys[MAX_ENTRY_NR];

unsigned int loops = 0;
unsigned int key_type = 0;
long hits = 0;
long drops = 0;

static int lookup_byte(__u32 index, void *data)
{
	unsigned int *value;

	if (index >= MAX_ENTRY_NR)
		return 1;

	value = bpf_map_lookup_elem(&byte_htab, &byte_keys[index]);
	if (value && *value == index)
		__sync_add_and_fetch(&hits, 1);
	else
		__sync_add_and_fetch(&drops, 1);

	return 0;
}

static int lookup_int_byte(__u32 index, void *data)
{
	unsigned int *value;

	if (index >= MAX_ENTRY_NR)
		return 1;

	value = bpf_map_lookup_elem(&int_byte_htab, &int_byte_keys[index]);
	if (value && *value == index)
		__sync_add_and_fetch(&hits, 1);
	else
		__sync_add_and_fetch(&drops, 1);

	return 0;
}

static int lookup_int_bytes(__u32 index, void *data)
{
	unsigned int *value;

	if (index >= MAX_ENTRY_NR)
		return 1;

	value = bpf_map_lookup_elem(&int_bytes_htab, &int_bytes_keys[index]);
	if (value && *value == index)
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

	/* Clear the hash value from previous lookup */
	str_keys[index].name.hash = 0;
	value = bpf_map_lookup_elem(&str_htab, &str_keys[index]);
	if (value && *value == index)
		__sync_add_and_fetch(&hits, 1);
	else
		__sync_add_and_fetch(&drops, 1);

	return 0;
}

static int lookup_int_str(__u32 index, void *data)
{
	unsigned int *value;

	if (index >= MAX_ENTRY_NR)
		return 1;

	int_str_keys[index].name.hash = 0;
	value = bpf_map_lookup_elem(&int_str_htab, &int_str_keys[index]);
	if (value && *value == index)
		__sync_add_and_fetch(&hits, 1);
	else
		__sync_add_and_fetch(&drops, 1);

	return 0;
}

static int lookup_int_strs(__u32 index, void *data)
{
	unsigned int *value;

	if (index >= MAX_ENTRY_NR)
		return 1;

	int_strs_keys[index].stor.hash = 0;
	value = bpf_map_lookup_elem(&int_strs_htab, &int_strs_keys[index]);
	if (value && *value == index)
		__sync_add_and_fetch(&hits, 1);
	else
		__sync_add_and_fetch(&drops, 1);

	return 0;
}

SEC("tp/syscalls/sys_enter_getpgid")
int htab_byte_lookup(void *ctx)
{
	if (!key_type)
		bpf_loop(loops, lookup_byte, NULL, 0);
	else if (key_type == 1)
		bpf_loop(loops, lookup_int_byte, NULL, 0);
	else
		bpf_loop(loops, lookup_int_bytes, NULL, 0);

	return 0;
}

SEC("tp/syscalls/sys_enter_getpgid")
int htab_str_lookup(void *ctx)
{
	if (!key_type)
		bpf_loop(loops, lookup_str, NULL, 0);
	else if (key_type == 1)
		bpf_loop(loops, lookup_int_str, NULL, 0);
	else
		bpf_loop(loops, lookup_int_strs, NULL, 0);

	return 0;
}
