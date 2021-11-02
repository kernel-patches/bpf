// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Google */
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* In the "real" real world, we would use BTF to generate a program which knows
 * about the old and new map ABI. To keep things simple we'll just use a
 * statically defined program which knows about them.
 */
struct allow_reads_key__old {
	uint32_t pid;
	int fd;
};
struct allow_reads_key__new {
	int fd;
	uint32_t pid;
};
struct allow_reads_value__old {
	bool do_drop;
};
struct allow_reads_value__new {
	bool do_drop;
};

/* Likewise, in the "real" real world we would simply generate a program
 * containing the fd of this map. For libbpf to generate a skeleton for us we
 * need to dupicate this definition.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 100);
	__type(key, struct allow_reads_key__old);
	__type(value, struct allow_reads_value__old);
} old_map SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 100);
	__type(key, struct allow_reads_key__new);
	__type(value, struct allow_reads_value__new);
} new_map SEC(".maps");

static inline void read_migrate_write(void *key, void *value)
{
	struct allow_reads_key__old old_key = {};
	struct allow_reads_key__new new_key = {};
	char old_value = 0;

	if (bpf_probe_read(&old_key, sizeof(old_key), key))
		return; /* Could write to a map here */
	if (bpf_probe_read(&old_value, sizeof(old_value), value))
		return; /* Could write to a map here */

	new_key.pid = old_key.pid;
	new_key.fd = old_key.fd;

	bpf_map_update_elem(&new_map, &new_key, &old_value, /*flags=*/0);
}

SEC("fentry/bpf_map_trace_update_elem")
int BPF_PROG(copy_on_write__update,
	     struct bpf_map *map, void *key,
	     void *value, u64 map_flags)
{
	if (map == &old_map)
		read_migrate_write(key, value);
	return 0;
}

static inline void read_migrate_delete(void *key)
{
	struct allow_reads_key__old old_key = {};
	struct allow_reads_key__new new_key = {};

	if (bpf_probe_read(&old_key, sizeof(old_key), key))
		return; /* Could write to a map here */

	new_key.pid = old_key.pid;
	new_key.fd = old_key.fd;

	bpf_map_delete_elem(&new_map, &new_key);
}

SEC("fentry/bpf_map_trace_delete_elem")
int BPF_PROG(copy_on_write__delete,
	     struct bpf_map *map, void *key)
{
	if (map == &old_map)
		read_migrate_delete(key);
	return 0;
}

SEC("iter/bpf_map_elem")
int bulk_migration(struct bpf_iter__bpf_map_elem *ctx)
{
	read_migrate_write(ctx->key, ctx->value);
	return 0;
}

char _license[] SEC("license") = "GPL";

