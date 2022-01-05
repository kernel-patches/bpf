// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2022 Google */
#include "map_trace.h"

noinline int bpf_map_trace_update_elem(struct bpf_map *map, void *key,
				       void *value, u64 map_flags)
{
	return 0;
}
ALLOW_ERROR_INJECTION(bpf_map_trace_update_elem, ERRNO);

noinline int bpf_map_trace_delete_elem(struct bpf_map *map, void *key)
{
	return 0;
}
ALLOW_ERROR_INJECTION(bpf_map_trace_delete_elem, ERRNO);

