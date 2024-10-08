// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2024. Huawei Technologies Co., Ltd */
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>

#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

struct bpf_map;

struct id_dname_key {
	int id;
	struct bpf_dynptr name;
};

struct dname_id_key {
	struct bpf_dynptr name;
	int id;
};

struct id_name_key {
	int id;
	char name[20];
};

struct dname_key {
	struct bpf_dynptr name;
};

struct dname_dname_key {
	struct bpf_dynptr name_1;
	struct bpf_dynptr name_2;
};

struct dname_dname_id_key {
	struct dname_dname_key names;
	__u64 id;
};

struct dname_id_id_id_key {
	struct bpf_dynptr name;
	__u64 id[3];
};

struct dname_dname_dname_key {
	struct bpf_dynptr name_1;
	struct bpf_dynptr name_2;
	struct bpf_dynptr name_3;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_DYNPTR_IN_KEY);
	__type(key, struct id_dname_key);
	__type(value, unsigned long);
	__uint(map_extra, 1024);
} htab_1 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_DYNPTR_IN_KEY);
	__type(key, struct dname_key);
	__type(value, unsigned long);
	__uint(map_extra, 1024);
} htab_2 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_DYNPTR_IN_KEY);
	__type(key, struct dname_dname_id_key);
	__type(value, unsigned long);
	__uint(map_extra, 1024);
} htab_3 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_DYNPTR_IN_KEY);
	__type(key, struct bpf_dynptr);
	__type(value, unsigned long);
	__uint(map_extra, 1024);
} htab_4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} ringbuf SEC(".maps");

char dynptr_buf[32] = {};

/* uninitialized dynptr */
SEC("fentry/" SYS_PREFIX "sys_nanosleep")
__failure __msg("dynptr-key expects dynptr at offset 8")
int BPF_PROG(uninit_dynptr)
{
	struct id_dname_key key;

	key.id = 100;
	bpf_map_lookup_elem(&htab_1, &key);

	return 0;
}

/* invalid dynptr */
SEC("fentry/" SYS_PREFIX "sys_nanosleep")
__failure __msg("dynptr-key expects dynptr at offset 8")
int BPF_PROG(invalid_dynptr)
{
	struct id_dname_key key;

	key.id = 100;
	bpf_ringbuf_reserve_dynptr(&ringbuf, 10, 0, &key.name);
	bpf_ringbuf_discard_dynptr(&key.name, 0);
	bpf_map_lookup_elem(&htab_1, &key);

	return 0;
}

/* expect no-dynptr got dynptr */
SEC("fentry/" SYS_PREFIX "sys_nanosleep")
__failure __msg("dynptr-key expects non-dynptr at offset 0")
int BPF_PROG(invalid_non_dynptr)
{
	struct dname_id_key key;

	__builtin_memcpy(dynptr_buf, "test", 4);
	bpf_dynptr_from_mem(dynptr_buf, 4, 0, &key.name);
	key.id = 100;
	bpf_map_lookup_elem(&htab_1, &key);

	return 0;
}

/* expect dynptr get non-dynptr */
SEC("fentry/" SYS_PREFIX "sys_nanosleep")
__failure __msg("dynptr-key expects dynptr at offset 8")
int BPF_PROG(no_dynptr)
{
	struct id_name_key key;

	key.id = 100;
	__builtin_memset(key.name, 0, sizeof(key.name));
	__builtin_memcpy(key.name, "test", 4);
	bpf_map_lookup_elem(&htab_1, &key);

	return 0;
}

/* malformed */
SEC("fentry/" SYS_PREFIX "sys_nanosleep")
__failure __msg("malformed dynptr-key at offset 8")
int BPF_PROG(malformed_dynptr)
{
	struct dname_dname_key key;

	bpf_dynptr_from_mem(dynptr_buf, 4, 0, &key.name_1);
	bpf_dynptr_from_mem(dynptr_buf, 4, 0, &key.name_2);

	bpf_map_lookup_elem(&htab_2, (void *)&key + 8);

	return 0;
}

/* expect no-dynptr got dynptr */
SEC("fentry/" SYS_PREFIX "sys_nanosleep")
__failure __msg("dynptr-key expects non-dynptr at offset 32")
int BPF_PROG(invalid_non_dynptr_2)
{
	struct dname_dname_dname_key key;

	bpf_dynptr_from_mem(dynptr_buf, 4, 0, &key.name_1);
	bpf_dynptr_from_mem(dynptr_buf, 4, 0, &key.name_2);
	bpf_dynptr_from_mem(dynptr_buf, 4, 0, &key.name_3);

	bpf_map_lookup_elem(&htab_3, &key);

	return 0;
}

/* expect dynptr get non-dynptr */
SEC("fentry/" SYS_PREFIX "sys_nanosleep")
__failure __msg("dynptr-key expects dynptr at offset 16")
int BPF_PROG(no_dynptr_2)
{
	struct dname_id_id_id_key key;

	bpf_dynptr_from_mem(dynptr_buf, 4, 0, &key.name);
	bpf_map_lookup_elem(&htab_3, &key);

	return 0;
}

/* misaligned */
SEC("fentry/" SYS_PREFIX "sys_nanosleep")
__failure __msg("R2 misaligned offset -28 for dynptr-key")
int BPF_PROG(misaligned_dynptr)
{
	struct dname_dname_key key;

	bpf_map_lookup_elem(&htab_1, (char *)&key + 4);

	return 0;
}

/* variable offset */
SEC("fentry/" SYS_PREFIX "sys_nanosleep")
__failure __msg("R2 variable offset prohibited for dynptr-key")
int BPF_PROG(variable_offset_dynptr)
{
	struct bpf_dynptr dynptr_1;
	struct bpf_dynptr dynptr_2;
	char *key;

	bpf_dynptr_from_mem(dynptr_buf, 4, 0, &dynptr_1);
	bpf_dynptr_from_mem(dynptr_buf, 4, 0, &dynptr_2);

	key = (char *)&dynptr_2;
	key = key + (bpf_get_prandom_u32() & 1) * 16;

	bpf_map_lookup_elem(&htab_2, key);

	return 0;
}

SEC("fentry/" SYS_PREFIX "sys_nanosleep")
__failure __msg("map dynptr-key requires stack ptr but got map_value")
int BPF_PROG(map_value_as_key)
{
	bpf_map_lookup_elem(&htab_1, dynptr_buf);

	return 0;
}

static int lookup_htab(struct bpf_map *map, struct id_dname_key *key, void *value, void *data)
{
	bpf_map_lookup_elem(&htab_1, key);
	return 0;
}

SEC("fentry/" SYS_PREFIX "sys_nanosleep")
__failure __msg("map dynptr-key requires stack ptr but got map_key")
int BPF_PROG(map_key_as_key)
{
	bpf_for_each_map_elem(&htab_1, lookup_htab, NULL, 0);
	return 0;
}

__noinline __weak int subprog_lookup_htab(struct bpf_dynptr *dynptr)
{
	bpf_map_lookup_elem(&htab_4, dynptr);
	return 0;
}

SEC("fentry/" SYS_PREFIX "sys_nanosleep")
__failure __msg("R2 type=dynptr_ptr expected=")
int BPF_PROG(subprog_dynptr)
{
	struct bpf_dynptr dynptr;

	bpf_dynptr_from_mem(dynptr_buf, 4, 0, &dynptr);
	subprog_lookup_htab(&dynptr);
	return 0;
}
