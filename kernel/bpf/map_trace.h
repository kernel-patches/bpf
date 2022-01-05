/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2022 Google */
#ifndef __BPF_MAP_TRACE_H_
#define __BPF_MAP_TRACE_H_

#include <linux/bpf.h>

/*
 * Map tracing hooks. They are called from some, but not all, bpf map types.
 * For those map types which call them, the only guarantee is that they are
 * called after the corresponding action (bpf_map_update_elem, etc.) takes
 * effect.
 */
int bpf_map_trace_update_elem(struct bpf_map *map, void *key,
			      void *value, u64 map_flags);

int bpf_map_trace_delete_elem(struct bpf_map *map, void *key);

#endif  // __BPF_MAP_TRACE_H_
