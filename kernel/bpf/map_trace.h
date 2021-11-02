// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2021 Google */
#pragma once

#include <linux/bpf.h>

/*
 * Map tracing hooks. They are called from some, but not all, bpf map types.
 * For those map types which call them, the only guarantee is that they are
 * called before the corresponding action (bpf_map_update_elem, etc.) takes
 * effect. Thus an fmod_ret program may use these hooks to prevent a map from
 * being mutated via the corresponding helpers.
 */
noinline int bpf_map_trace_update_elem(struct bpf_map *map, void *key,
				       void *value, u64 map_flags);

noinline int bpf_map_trace_delete_elem(struct bpf_map *map, void *key);

