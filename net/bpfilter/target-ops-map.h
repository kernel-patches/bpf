/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 */

#ifndef NET_BPFILTER_TARGET_OPS_MAP_H
#define NET_BPFILTER_TARGET_OPS_MAP_H

#include "map-common.h"

#include <linux/err.h>

#include <errno.h>
#include <string.h>

#include "target.h"

struct target_ops_map {
	struct hsearch_data index;
};

static inline int create_target_ops_map(struct target_ops_map *map, size_t nelem)
{
	return create_map(&map->index, nelem);
}

static inline const struct target_ops *target_ops_map_find(struct target_ops_map *map,
							   const char *name)
{
	const size_t namelen = strnlen(name, BPFILTER_EXTENSION_MAXNAMELEN);

	if (namelen < BPFILTER_EXTENSION_MAXNAMELEN)
		return map_find(&map->index, name);

	return ERR_PTR(-EINVAL);
}

static inline int target_ops_map_insert(struct target_ops_map *map,
					const struct target_ops *target_ops)
{
	return map_insert(&map->index, target_ops->name, (void *)target_ops);
}

static inline void free_target_ops_map(struct target_ops_map *map)
{
	free_map(&map->index);
}

#endif // NET_BPFILTER_TARGET_OPS_MAP_H
