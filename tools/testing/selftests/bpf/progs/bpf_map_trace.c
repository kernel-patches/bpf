// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Google */
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>
#include <string.h>

#include "bpf_map_trace_common.h"

#define DECLARE_MAP(name, map_type) \
		struct { \
			__uint(type, map_type); \
			__uint(max_entries, __ACCESS_LOC__MAX); \
			__type(key, u32); \
			__type(value, u32); \
		} name SEC(".maps")

DECLARE_MAP(array_map, BPF_MAP_TYPE_ARRAY);
DECLARE_MAP(percpu_array_map, BPF_MAP_TYPE_PERCPU_ARRAY);
DECLARE_MAP(hash_map, BPF_MAP_TYPE_HASH);
DECLARE_MAP(percpu_hash_map, BPF_MAP_TYPE_PERCPU_HASH);
DECLARE_MAP(lru_hash_map, BPF_MAP_TYPE_LRU_HASH);
DECLARE_MAP(percpu_lru_hash_map, BPF_MAP_TYPE_LRU_PERCPU_HASH);

static inline void __log_location(void *map,
				  enum MapAccessLocations location)
{
	u32 key = location;
	u32 val = 1;

	bpf_map_update_elem(map, &key, &val, /*flags=*/0);
}

static inline void log_location(struct bpf_map *map,
				enum MapAccessLocations location)
{
	if (map == &array_map)
		__log_location(&array_map, location);
	if (map == &percpu_array_map)
		__log_location(&percpu_array_map, location);
	if (map == &hash_map)
		__log_location(&hash_map, location);
	if (map == &percpu_hash_map)
		__log_location(&percpu_hash_map, location);
	if (map == &lru_hash_map)
		__log_location(&lru_hash_map, location);
	if (map == &percpu_lru_hash_map)
		__log_location(&percpu_lru_hash_map, location);
}

SEC("fentry/bpf_map_trace_update_elem")
int BPF_PROG(fentry__bpf_map_trace_update_elem,
	     struct bpf_map *map, void *key,
	     void *value, u64 map_flags)
{
	log_location(map, ACCESS_LOC__TRACE_UPDATE);
	return 0;
}

SEC("fentry/bpf_map_trace_delete_elem")
int BPF_PROG(fentry__bpf_map_trace_delete_elem,
	     struct bpf_map *map, void *key)
{
	log_location(map, ACCESS_LOC__TRACE_DELETE);
	return 0;
}

static inline void do_map_accesses(void *map)
{
	u32 key = ACCESS_LOC__APP;
	u32 val = 1;

	bpf_map_update_elem(map, &key, &val, /*flags=*/0);
	bpf_map_delete_elem(map, &key);
}

SEC("fentry/__x64_sys_write")
int BPF_PROG(fentry__x64_sys_write, struct pt_regs *regs, int ret)
{
	/*
	 * Trigger an update and a delete for every map type under test.
	 * We want to verify that bpf_map_trace_{update,delete}_elem() fire
	 * for each map type.
	 */
	do_map_accesses(&array_map);
	do_map_accesses(&percpu_array_map);
	do_map_accesses(&hash_map);
	do_map_accesses(&percpu_hash_map);
	do_map_accesses(&lru_hash_map);
	do_map_accesses(&percpu_lru_hash_map);
	return 0;
}

