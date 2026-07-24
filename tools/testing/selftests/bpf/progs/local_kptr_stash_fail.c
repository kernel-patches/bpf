// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../bpf_experimental.h"
#include "bpf_misc.h"

struct node_data {
	long key;
	long data;
	struct bpf_rb_node node;
};

struct map_value {
	struct node_data __kptr *node;
};

struct node_data2 {
	long key[4];
};

struct refcount_only {
	struct bpf_refcount refcount;
	long canary;
};

struct refcount_only_map_value {
	struct refcount_only __kptr *node;
};

/* This is necessary so that LLVM generates BTF for node_data struct
 * If it's not included, a fwd reference for node_data will be generated but
 * no struct. Example BTF of "node" field in map_value when not included:
 *
 * [10] PTR '(anon)' type_id=35
 * [34] FWD 'node_data' fwd_kind=struct
 * [35] TYPE_TAG 'kptr_ref' type_id=34
 */
struct node_data *just_here_because_btf_bug;
struct refcount_only *refcount_only_btf;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct map_value);
	__uint(max_entries, 2);
} some_nodes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct refcount_only_map_value);
	__uint(max_entries, 1);
} refcount_only_stash SEC(".maps");

extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;

SEC("tc")
__failure __msg("invalid kptr access, R2 type=ptr_node_data2 expected=ptr_node_data")
long stash_rb_nodes(void *ctx)
{
	struct map_value *mapval;
	struct node_data2 *res;
	int idx = 0;

	mapval = bpf_map_lookup_elem(&some_nodes, &idx);
	if (!mapval)
		return 1;

	res = bpf_obj_new(typeof(*res));
	if (!res)
		return 1;
	res->key[0] = 40;

	res = bpf_kptr_xchg(&mapval->node, res);
	if (res)
		bpf_obj_drop(res);
	return 0;
}

SEC("tc")
__failure __msg("R1 must have zero offset when passed to release func")
long drop_rb_node_off(void *ctx)
{
	struct map_value *mapval;
	struct node_data *res;
	int idx = 0;

	mapval = bpf_map_lookup_elem(&some_nodes, &idx);
	if (!mapval)
		return 1;

	res = bpf_obj_new(typeof(*res));
	if (!res)
		return 1;
	/* Try releasing with graph node offset */
	bpf_obj_drop(&res->node);
	return 0;
}

/*
 * A direct load of a referenced map kptr is a non-owning reference. The
 * acquire can return NULL if another invocation exchanges the map kptr and
 * drops its last owning reference before refcount_inc_not_zero().
 */
SEC("?tc")
__failure __msg("invalid mem access 'ptr_or_null_'")
long refcount_acquire_unchecked_load(void *ctx)
{
	struct refcount_only_map_value *mapval;
	struct refcount_only *node, *ref;
	long canary;
	int key = 0;

	mapval = bpf_map_lookup_elem(&refcount_only_stash, &key);
	if (!mapval)
		return 0;

	bpf_rcu_read_lock();
	node = mapval->node;
	if (!node) {
		bpf_rcu_read_unlock();
		return 0;
	}
	ref = bpf_refcount_acquire(node);
	bpf_rcu_read_unlock();

	canary = ref->canary;
	bpf_obj_drop(ref);
	return canary;
}

SEC("?tc")
__failure __msg("Possibly NULL pointer passed")
long refcount_acquire_unchecked_drop(void *ctx)
{
	struct refcount_only_map_value *mapval;
	struct refcount_only *node, *ref;
	int key = 0;

	mapval = bpf_map_lookup_elem(&refcount_only_stash, &key);
	if (!mapval)
		return 0;

	bpf_rcu_read_lock();
	node = mapval->node;
	if (!node) {
		bpf_rcu_read_unlock();
		return 0;
	}
	ref = bpf_refcount_acquire(node);
	bpf_rcu_read_unlock();

	bpf_obj_drop(ref);
	return 0;
}

SEC("?tc")
__success
long refcount_acquire_checked(void *ctx)
{
	struct refcount_only_map_value *mapval;
	struct refcount_only *node, *ref;
	long canary;
	int key = 0;

	mapval = bpf_map_lookup_elem(&refcount_only_stash, &key);
	if (!mapval)
		return 0;

	bpf_rcu_read_lock();
	node = mapval->node;
	if (!node) {
		bpf_rcu_read_unlock();
		return 0;
	}
	ref = bpf_refcount_acquire(node);
	bpf_rcu_read_unlock();
	if (!ref)
		return 0;

	canary = ref->canary;
	bpf_obj_drop(ref);
	return canary;
}

char _license[] SEC("license") = "GPL";
