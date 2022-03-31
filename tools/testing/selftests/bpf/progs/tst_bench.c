// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2022. Huawei Technologies Co., Ltd */
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct bpf_map;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, 4);
} array SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(value_size, 4);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} htab SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_TST);
	__uint(value_size, 4);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} tst SEC(".maps");

char _license[] SEC("license") = "GPL";

long hits = 0;
long drops = 0;

static int lookup_htab(struct bpf_map *map, __u32 *key, void *value, void *data)
{
	__u32 *index;

	index = bpf_map_lookup_elem(&htab, value);
	if (index && *index == *key)
		__sync_add_and_fetch(&hits, 1);
	else
		__sync_add_and_fetch(&drops, 1);

	return 0;
}

static int lookup_tst(struct bpf_map *map, __u32 *key, void *value, void *data)
{
	__u32 *index;

	index = bpf_map_lookup_elem(&tst, value);
	if (index && *index == *key)
		__sync_add_and_fetch(&hits, 1);
	else
		__sync_add_and_fetch(&drops, 1);

	return 0;
}

SEC("tp/syscalls/sys_enter_getpgid")
int htab_lookup(void *ctx)
{
	bpf_for_each_map_elem(&array, lookup_htab, NULL, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_getpgid")
int tst_lookup(void *ctx)
{
	bpf_for_each_map_elem(&array, lookup_tst, NULL, 0);
	return 0;
}
