/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BPF_CGROUP_STORAGE_H
#define _BPF_CGROUP_STORAGE_H

#include <linux/bpf.h>
#include <linux/bpf-cgroup.h>

static inline enum bpf_cgroup_storage_type cgroup_storage_type(
	struct bpf_map *map)
{
	if (map->map_type == BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE)
		return BPF_CGROUP_STORAGE_PERCPU;

	return BPF_CGROUP_STORAGE_SHARED;
}

#endif
