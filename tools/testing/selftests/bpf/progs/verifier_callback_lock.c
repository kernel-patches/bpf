// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

struct bpf_map;

struct lock_value {
	struct bpf_spin_lock lock;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, int);
	__type(value, struct lock_value);
} lock_map SEC(".maps");

struct callback_ctx {
	struct lock_value *value;
};

static long lock_different_value(struct bpf_map *map, int *key,
				 struct lock_value *value, struct callback_ctx *ctx)
{
	bpf_spin_lock(&value->lock);
	bpf_spin_unlock(&ctx->value->lock);
	return 0;
}

static long nest_lock_different_value(struct bpf_map *map, int *key,
				      struct lock_value *value, void *data)
{
	struct callback_ctx ctx = { .value = value };

	bpf_for_each_map_elem(&lock_map, lock_different_value, &ctx, 0);
	return 0;
}

SEC("?tc")
__description("callback map value has a distinct lock identity")
__failure __msg("bpf_spin_unlock of different lock")
int callback_value_lock_identity(void *ctx)
{
	bpf_for_each_map_elem(&lock_map, nest_lock_different_value, NULL, 0);
	return 0;
}

static long lock_same_value(struct bpf_map *map, int *key,
			    struct lock_value *value, void *data)
{
	bpf_spin_lock(&value->lock);
	bpf_spin_unlock(&value->lock);
	return 0;
}

static long nest_lock_same_value(struct bpf_map *map, int *key,
				 struct lock_value *value, void *data)
{
	bpf_for_each_map_elem(&lock_map, lock_same_value, NULL, 0);
	return 0;
}

SEC("?tc")
__description("nested callback can lock its own map value")
__success
int callback_value_lock_identity_same(void *ctx)
{
	bpf_for_each_map_elem(&lock_map, nest_lock_same_value, NULL, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
