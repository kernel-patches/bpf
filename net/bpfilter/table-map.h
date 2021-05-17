/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 */

#ifndef NET_BPFILTER_TABLE_MAP_H
#define NET_BPFILTER_TABLE_MAP_H

#include "map-common.h"
#include "table.h"

struct table_map {
	struct hsearch_data index;
};

static inline int create_table_map(struct table_map *map, size_t nelem)
{
	return create_map(&map->index, nelem);
}

static inline struct table *table_map_find(struct table_map *map, const char *name)
{
	return map_find(&map->index, name);
}

static inline int table_map_update(struct table_map *map, const char *name, void *data)
{
	return map_update(&map->index, name, data);
}

static inline int table_map_insert(struct table_map *map, struct table *table)
{
	return map_insert(&map->index, table->name, table);
}

static inline void free_table_map(struct table_map *map)
{
	free_map(&map->index);
}

#endif // NET_BPFILTER_TABLE_MAP_H
