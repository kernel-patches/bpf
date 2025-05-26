// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2025. Huawei Technologies Co., Ltd */
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

#include "bpf_experimental.h"
#include "bpf_misc.h"

struct plain_value {
	__u64 data[2];
};

struct plain_node {
	__u64 data[8];
	struct bpf_list_node node;
};

struct map_value {
	struct plain_value __kptr * ptr;
	struct bpf_timer timer;
	struct bpf_spin_lock lock;
	struct bpf_list_head head __contains(plain_node, node);
};

struct simple_map_value {
	struct plain_value __kptr * ptr;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, struct map_value);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} map_1 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__type(key, int);
	__type(value, struct simple_map_value);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} map_2 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__type(key, int);
	__type(value, struct simple_map_value);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} map_3 SEC(".maps");

char _license[] SEC("license") = "GPL";

SEC("syscall")
int test_special_fields(void *ctx)
{
	struct plain_value *ptr, *old_ptr;
	struct map_value ini = {};
	struct plain_node *node;
	struct map_value *v;
	int key = 0, err;

	err = bpf_map_update_elem(&map_1, &key, &ini, BPF_ANY);
	if (err)
		return 1;

	v = bpf_map_lookup_elem(&map_1, &key);
	if (!v)
		return 2;

	err = bpf_map_delete_elem(&map_1, &key);
	if (err)
		return 3;

	ptr = bpf_obj_new(typeof(*ptr));
	if (!ptr)
		return 4;

	old_ptr = bpf_kptr_xchg(&v->ptr, ptr);
	if (old_ptr)
		bpf_obj_drop(old_ptr);

	err = bpf_timer_init(&v->timer, &map_1, 0);
	if (err)
		return 5;

	node = bpf_obj_new(typeof(*node));
	if (!node)
		return 6;

	bpf_spin_lock(&v->lock);
	bpf_list_push_back(&v->head, &node->node);
	bpf_spin_unlock(&v->lock);

	return 0;
}

SEC("syscall")
int test_percpu_special_fields(void *ctx)
{
	struct plain_value *ptr, *old_ptr;
	struct simple_map_value ini = {};
	struct simple_map_value *v;
	int key = 0, err;

	err = bpf_map_update_elem(&map_2, &key, &ini, BPF_ANY);
	if (err)
		return 1;

	v = bpf_map_lookup_elem(&map_2, &key);
	if (!v)
		return 2;

	err = bpf_map_delete_elem(&map_2, &key);
	if (err)
		return 3;

	ptr = bpf_obj_new(typeof(*ptr));
	if (!ptr)
		return 4;

	old_ptr = bpf_kptr_xchg(&v->ptr, ptr);
	if (old_ptr)
		bpf_obj_drop(old_ptr);

	return 0;
}

SEC("syscall")
int test_local_stor_special_fields(void *ctx)
{
	struct plain_value *ptr, *old_ptr;
	struct simple_map_value *v;
	struct task_struct *cur;
	int err;

	cur = bpf_get_current_task_btf();
	if (!cur)
		return 1;

	v = bpf_task_storage_get(&map_3, cur, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!v)
		return 2;

	err = bpf_task_storage_delete(&map_3, cur);
	if (err)
		return 3;

	ptr = bpf_obj_new(typeof(*ptr));
	if (!ptr)
		return 4;

	old_ptr = bpf_kptr_xchg(&v->ptr, ptr);
	if (old_ptr)
		bpf_obj_drop(old_ptr);

	return 0;
}
