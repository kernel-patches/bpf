/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 */

#ifndef NET_BPFILTER_MAP_COMMON_H
#define NET_BPFILTER_MAP_COMMON_H

#define _GNU_SOURCE

#include <search.h>

int create_map(struct hsearch_data *htab, size_t nelem);
void *map_find(struct hsearch_data *htab, const char *name);
int map_insert(struct hsearch_data *htab, const char *name, void *data);
int map_update(struct hsearch_data *htab, const char *name, void *data);
void free_map(struct hsearch_data *htab);

#endif // NET_BPFILTER_MAP_COMMON_H
