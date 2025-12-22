// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <rdma/ib_verbs.h>

#include "frmr_pools.h"

static int push_handle_to_queue_locked(struct frmr_queue *queue, u32 handle)
{
	u32 tmp = queue->ci % NUM_HANDLES_PER_PAGE;
	struct frmr_handles_page *page;

	if (queue->ci >= queue->num_pages * NUM_HANDLES_PER_PAGE) {
		page = kzalloc(sizeof(*page), GFP_ATOMIC);
		if (!page)
			return -ENOMEM;
		queue->num_pages++;
		list_add_tail(&page->list, &queue->pages_list);
	} else {
		page = list_last_entry(&queue->pages_list,
				       struct frmr_handles_page, list);
	}

	page->handles[tmp] = handle;
	queue->ci++;
	return 0;
}

static u32 pop_handle_from_queue_locked(struct frmr_queue *queue)
{
	u32 tmp = (queue->ci - 1) % NUM_HANDLES_PER_PAGE;
	struct frmr_handles_page *page;
	u32 handle;

	page = list_last_entry(&queue->pages_list, struct frmr_handles_page,
			       list);
	handle = page->handles[tmp];
	queue->ci--;

	if (!tmp) {
		list_del(&page->list);
		queue->num_pages--;
		kfree(page);
	}

	return handle;
}

static bool pop_frmr_handles_page(struct ib_frmr_pool *pool,
				  struct frmr_queue *queue,
				  struct frmr_handles_page **page, u32 *count)
{
	spin_lock(&pool->lock);
	if (list_empty(&queue->pages_list)) {
		spin_unlock(&pool->lock);
		return false;
	}

	*page = list_first_entry(&queue->pages_list, struct frmr_handles_page,
				 list);
	list_del(&(*page)->list);
	queue->num_pages--;

	/* If this is the last page, count may be less than
	 * NUM_HANDLES_PER_PAGE.
	 */
	if (queue->ci >= NUM_HANDLES_PER_PAGE)
		*count = NUM_HANDLES_PER_PAGE;
	else
		*count = queue->ci;

	queue->ci -= *count;
	spin_unlock(&pool->lock);
	return true;
}

static void destroy_frmr_pool(struct ib_device *device,
			      struct ib_frmr_pool *pool)
{
	struct ib_frmr_pools *pools = device->frmr_pools;
	struct frmr_handles_page *page;
	u32 count;

	while (pop_frmr_handles_page(pool, &pool->queue, &page, &count)) {
		pools->pool_ops->destroy_frmrs(device, page->handles, count);
		kfree(page);
	}

	rb_erase(&pool->node, &pools->rb_root);
	kfree(pool);
}

/*
 * Initialize the FRMR pools for a device.
 *
 * @device: The device to initialize the FRMR pools for.
 * @pool_ops: The pool operations to use.
 *
 * Returns 0 on success, negative error code on failure.
 */
int ib_frmr_pools_init(struct ib_device *device,
		       const struct ib_frmr_pool_ops *pool_ops)
{
	struct ib_frmr_pools *pools;

	pools = kzalloc(sizeof(*pools), GFP_KERNEL);
	if (!pools)
		return -ENOMEM;

	pools->rb_root = RB_ROOT;
	rwlock_init(&pools->rb_lock);
	pools->pool_ops = pool_ops;

	device->frmr_pools = pools;
	return 0;
}
EXPORT_SYMBOL(ib_frmr_pools_init);

/*
 * Clean up the FRMR pools for a device.
 *
 * @device: The device to clean up the FRMR pools for.
 *
 * Call cleanup only after all FRMR handles have been pushed back to the pool
 * and no other FRMR operations are allowed to run in parallel.
 * Ensuring this allows us to save synchronization overhead in pop and push
 * operations.
 */
void ib_frmr_pools_cleanup(struct ib_device *device)
{
	struct ib_frmr_pools *pools = device->frmr_pools;
	struct rb_node *node = rb_first(&pools->rb_root);
	struct ib_frmr_pool *pool;

	while (node) {
		struct rb_node *next = rb_next(node);

		pool = rb_entry(node, struct ib_frmr_pool, node);
		destroy_frmr_pool(device, pool);
		node = next;
	}

	kfree(pools);
	device->frmr_pools = NULL;
}
EXPORT_SYMBOL(ib_frmr_pools_cleanup);

static int compare_keys(struct ib_frmr_key *key1, struct ib_frmr_key *key2)
{
	int res;

	res = key1->ats - key2->ats;
	if (res)
		return res;

	res = key1->access_flags - key2->access_flags;
	if (res)
		return res;

	res = key1->vendor_key - key2->vendor_key;
	if (res)
		return res;

	res = key1->kernel_vendor_key - key2->kernel_vendor_key;
	if (res)
		return res;

	/*
	 * allow using handles that support more DMA blocks, up to twice the
	 * requested number
	 */
	res = key1->num_dma_blocks - key2->num_dma_blocks;
	if (res > 0 && res < key2->num_dma_blocks)
		return 0;

	return res;
}

static struct ib_frmr_pool *ib_frmr_pool_find(struct ib_frmr_pools *pools,
					      struct ib_frmr_key *key)
{
	struct rb_node *node = pools->rb_root.rb_node;
	struct ib_frmr_pool *pool;
	int cmp;

	/* find operation is done under read lock for performance reasons.
	 * The case of threads failing to find the same pool and creating it
	 * is handled by the create_frmr_pool function.
	 */
	read_lock(&pools->rb_lock);
	while (node) {
		pool = rb_entry(node, struct ib_frmr_pool, node);
		cmp = compare_keys(&pool->key, key);
		if (cmp < 0) {
			node = node->rb_right;
		} else if (cmp > 0) {
			node = node->rb_left;
		} else {
			read_unlock(&pools->rb_lock);
			return pool;
		}
	}

	read_unlock(&pools->rb_lock);

	return NULL;
}

static struct ib_frmr_pool *create_frmr_pool(struct ib_device *device,
					     struct ib_frmr_key *key)
{
	struct rb_node **new = &device->frmr_pools->rb_root.rb_node,
		       *parent = NULL;
	struct ib_frmr_pools *pools = device->frmr_pools;
	struct ib_frmr_pool *pool;
	int cmp;

	pool = kzalloc(sizeof(*pool), GFP_KERNEL);
	if (!pool)
		return ERR_PTR(-ENOMEM);

	memcpy(&pool->key, key, sizeof(*key));
	INIT_LIST_HEAD(&pool->queue.pages_list);
	spin_lock_init(&pool->lock);

	write_lock(&pools->rb_lock);
	while (*new) {
		parent = *new;
		cmp = compare_keys(
			&rb_entry(parent, struct ib_frmr_pool, node)->key, key);
		if (cmp < 0)
			new = &((*new)->rb_left);
		else
			new = &((*new)->rb_right);
		/* If a different thread has already created the pool, return
		 * it. The insert operation is done under the write lock so we
		 * are sure that the pool is not inserted twice.
		 */
		if (cmp == 0) {
			write_unlock(&pools->rb_lock);
			kfree(pool);
			return rb_entry(parent, struct ib_frmr_pool, node);
		}
	}

	rb_link_node(&pool->node, parent, new);
	rb_insert_color(&pool->node, &pools->rb_root);

	write_unlock(&pools->rb_lock);

	return pool;
}

static int get_frmr_from_pool(struct ib_device *device,
			      struct ib_frmr_pool *pool, struct ib_mr *mr)
{
	struct ib_frmr_pools *pools = device->frmr_pools;
	u32 handle;
	int err;

	spin_lock(&pool->lock);
	if (pool->queue.ci == 0) {
		spin_unlock(&pool->lock);
		err = pools->pool_ops->create_frmrs(device, &pool->key, &handle,
						    1);
		if (err)
			return err;
	} else {
		handle = pop_handle_from_queue_locked(&pool->queue);
		spin_unlock(&pool->lock);
	}

	mr->frmr.pool = pool;
	mr->frmr.handle = handle;

	return 0;
}

/*
 * Pop an FRMR handle from the pool.
 *
 * @device: The device to pop the FRMR handle from.
 * @mr: The MR to pop the FRMR handle from.
 *
 * Returns 0 on success, negative error code on failure.
 */
int ib_frmr_pool_pop(struct ib_device *device, struct ib_mr *mr)
{
	struct ib_frmr_pools *pools = device->frmr_pools;
	struct ib_frmr_pool *pool;

	WARN_ON_ONCE(!device->frmr_pools);
	pool = ib_frmr_pool_find(pools, &mr->frmr.key);
	if (!pool) {
		pool = create_frmr_pool(device, &mr->frmr.key);
		if (IS_ERR(pool))
			return PTR_ERR(pool);
	}

	return get_frmr_from_pool(device, pool, mr);
}
EXPORT_SYMBOL(ib_frmr_pool_pop);

/*
 * Push an FRMR handle back to the pool.
 *
 * @device: The device to push the FRMR handle to.
 * @mr: The MR containing the FRMR handle to push back to the pool.
 *
 * Returns 0 on success, negative error code on failure.
 */
int ib_frmr_pool_push(struct ib_device *device, struct ib_mr *mr)
{
	struct ib_frmr_pool *pool = mr->frmr.pool;
	int ret;

	spin_lock(&pool->lock);
	ret = push_handle_to_queue_locked(&pool->queue, mr->frmr.handle);
	spin_unlock(&pool->lock);

	return ret;
}
EXPORT_SYMBOL(ib_frmr_pool_push);
