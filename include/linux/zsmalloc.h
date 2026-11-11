/*
 * zsmalloc memory allocator
 *
 * Copyright (C) 2011  Nitin Gupta
 * Copyright (C) 2012, 2013 Minchan Kim
 *
 * This code is released using a dual license strategy: BSD/GPL
 * You can choose the license that better fits your requirements.
 *
 * Released under the terms of 3-clause BSD License
 * Released under the terms of GNU General Public License Version 2.0
 */

#ifndef _ZS_MALLOC_H_
#define _ZS_MALLOC_H_

#include <linux/compiler.h>
#include <linux/types.h>

struct zs_pool_stats {
	/* How many pages were migrated (freed) */
	atomic_long_t pages_compacted;
};

/*
 * zsmalloc writes object location into the handle, keeps a back-pointer to
 * it, and updates it asynchronously when the object moves (compaction, page
 * migration).  Therefore the owner must not modify or copy the handle, must
 * not put it on the stack or misalign it (e.g. inside a __packed struct),
 * and must keep it allocated until zs_free() or zs_rebind_handle().
 */
struct zs_handle {
	unsigned long __private obj;
};

static inline void zs_handle_init(struct zs_handle *handle)
{
	ACCESS_PRIVATE(handle, obj) = 0;
}

static inline bool zs_handle_is_allocated(const struct zs_handle *handle)
{
	return READ_ONCE(ACCESS_PRIVATE(handle, obj)) != 0;
}

struct zs_pool;
struct scatterlist;

struct zs_pool *zs_create_pool(const char *name);
void zs_destroy_pool(struct zs_pool *pool);

int zs_store(struct zs_pool *pool, struct zs_handle *handle, const void *src,
	     size_t size, gfp_t flags, const int nid);
void zs_free(struct zs_pool *pool, struct zs_handle *handle);
void zs_rebind_handle(struct zs_pool *pool, struct zs_handle *dst,
		      struct zs_handle *src);

size_t zs_huge_class_size(struct zs_pool *pool);

unsigned long zs_get_total_pages(struct zs_pool *pool);
unsigned long zs_compact(struct zs_pool *pool);

unsigned int zs_lookup_class_index(struct zs_pool *pool, unsigned int size);

void zs_pool_stats(struct zs_pool *pool, struct zs_pool_stats *stats);

void zs_obj_read_sg_begin(struct zs_pool *pool, const struct zs_handle *handle,
			  struct scatterlist *sg, size_t mem_len);
void zs_obj_read_sg_end(struct zs_pool *pool, const struct zs_handle *handle);

extern const struct movable_operations zsmalloc_mops;

#endif
