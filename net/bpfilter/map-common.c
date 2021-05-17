// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 */

#include "map-common.h"

#include <linux/err.h>

#include <errno.h>
#include <string.h>

int create_map(struct hsearch_data *htab, size_t nelem)
{
	memset(htab, 0, sizeof(*htab));
	if (!hcreate_r(nelem, htab))
		return -errno;

	return 0;
}

void *map_find(struct hsearch_data *htab, const char *name)
{
	const ENTRY needle = { .key = (char *)name };
	ENTRY *found;

	if (!hsearch_r(needle, FIND, &found, htab))
		return ERR_PTR(-ENOENT);

	return found->data;
}

int map_update(struct hsearch_data *htab, const char *name, void *data)
{
	const ENTRY needle = { .key = (char *)name, .data = data };
	ENTRY *found;

	if (!hsearch_r(needle, ENTER, &found, htab))
		return -errno;

	found->key = (char *)name;
	found->data = data;

	return 0;
}

int map_insert(struct hsearch_data *htab, const char *name, void *data)
{
	const ENTRY needle = { .key = (char *)name, .data = data };
	ENTRY *found;

	if (!hsearch_r(needle, ENTER, &found, htab))
		return -errno;

	if (found->data != data)
		return -EEXIST;

	return 0;
}

void free_map(struct hsearch_data *htab)
{
	hdestroy_r(htab);
}
