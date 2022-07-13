// SPDX-License-Identifier: GPL-2.0-only

/* Pifomaps queue packets
 */
#include <linux/spinlock.h>
#include <linux/bpf.h>
#include <linux/bitops.h>
#include <linux/btf_ids.h>
#include <linux/minmax.h>
#include <net/xdp.h>
#include <linux/filter.h>
#include <trace/events/xdp.h>

#define PIFO_CREATE_FLAG_MASK \
	(BPF_F_NUMA_NODE | BPF_F_RDONLY | BPF_F_WRONLY)

struct bpf_pifo_element {
	struct bpf_pifo_element *next;
	char data[];
};

union bpf_pifo_item {
	struct bpf_pifo_element elem;
	struct xdp_frame frame;
};

struct bpf_pifo_element_cache {
	u32 free_elems;
	struct bpf_pifo_element *elements[];
};

struct bpf_pifo_bucket {
	union bpf_pifo_item *head, *tail;
	u32 elem_count;
};

struct bpf_pifo_queue {
	struct bpf_pifo_bucket *buckets;
	unsigned long *bitmap;
	unsigned long **lvl_bitmap;
	u64 min_rank;
	u32 range;
	u32 levels;
};

struct bpf_pifo_map {
	struct bpf_map map;
	struct bpf_pifo_queue *q_primary;
	struct bpf_pifo_queue *q_secondary;
	unsigned long num_queued;
	spinlock_t lock; /* protects enqueue / dequeue */

	size_t elem_size;
	struct bpf_pifo_element_cache *elem_cache;
	char elements[] __aligned(8);
};

static struct bpf_pifo_element *elem_cache_get(struct bpf_pifo_element_cache *cache)
{
	if (unlikely(!cache->free_elems))
		return NULL;
	return cache->elements[--cache->free_elems];
}

static void elem_cache_put(struct bpf_pifo_element_cache *cache,
			   struct bpf_pifo_element *elem)
{
	cache->elements[cache->free_elems++] = elem;
}

static bool pifo_map_is_full(struct bpf_pifo_map *pifo)
{
	return pifo->num_queued >= pifo->map.max_entries;
}

static bool pifo_queue_is_empty(struct bpf_pifo_queue *queue)
{
	/* first word in bitmap is always the top-level map */
	return !queue->bitmap[0];
}

static void pifo_queue_free(struct bpf_pifo_queue *q)
{
	bpf_map_area_free(q->buckets);
	bpf_map_area_free(q->bitmap);
	bpf_map_area_free(q->lvl_bitmap);
	kfree(q);
}

static struct bpf_pifo_queue *pifo_queue_alloc(u32 range, u32 min_rank, int numa_node)
{
	u32 num_longs = 0, offset = 0, i, lvl, levels;
	struct bpf_pifo_queue *q;

	levels = __KERNEL_DIV_ROUND_UP(ilog2(range), ilog2(BITS_PER_TYPE(long)));
	for (i = 0, lvl = 1; i < levels; i++) {
		num_longs += lvl;
		lvl *= BITS_PER_TYPE(long);
	}

	q = kzalloc(sizeof(*q), GFP_USER | __GFP_ACCOUNT);
	if (!q)
		return NULL;
	q->buckets = bpf_map_area_alloc(sizeof(struct bpf_pifo_bucket) * range,
					numa_node);
	if (!q->buckets)
		goto err;

	q->bitmap = bpf_map_area_alloc(sizeof(unsigned long) * num_longs,
				       numa_node);
	if (!q->bitmap)
		goto err;

	q->lvl_bitmap = bpf_map_area_alloc(sizeof(unsigned long *) * levels,
					   numa_node);
	for (i = 0, lvl = 1; i < levels; i++) {
		q->lvl_bitmap[i] = &q->bitmap[offset];
		offset += lvl;
		lvl *= BITS_PER_TYPE(long);
	}
	q->levels = levels;
	q->range = range;
	q->min_rank = min_rank;
	return q;

err:
	pifo_queue_free(q);
	return NULL;
}

static int pifo_map_init_map(struct bpf_pifo_map *pifo, union bpf_attr *attr,
			     size_t elem_size, u32 range)
{
	int err = -ENOMEM;

	/* Packet map is special, we don't want BPF writing straight to it
	 */
	if (attr->map_type != BPF_MAP_TYPE_PIFO_GENERIC)
		attr->map_flags |= BPF_F_RDONLY_PROG;

	bpf_map_init_from_attr(&pifo->map, attr);

	pifo->q_primary = pifo_queue_alloc(range, 0, pifo->map.numa_node);
	if (!pifo->q_primary)
		return -ENOMEM;

	pifo->q_secondary = pifo_queue_alloc(range, range, pifo->map.numa_node);
	if (!pifo->q_secondary)
		goto err_queue;

	if (attr->map_type == BPF_MAP_TYPE_PIFO_GENERIC) {
		size_t cache_size;
		int i;

		cache_size = sizeof(void *) * attr->max_entries +
			sizeof(struct bpf_pifo_element_cache);
		pifo->elem_cache = bpf_map_area_alloc(cache_size,
						      pifo->map.numa_node);
		if (!pifo->elem_cache)
			goto err;

		for (i = 0; i < attr->max_entries; i++)
			pifo->elem_cache->elements[i] = (void *)&pifo->elements[i * elem_size];
		pifo->elem_cache->free_elems = attr->max_entries;
	}

	return 0;

err:
	pifo_queue_free(pifo->q_secondary);
err_queue:
	pifo_queue_free(pifo->q_primary);
	return err;
}

static struct bpf_map *pifo_map_alloc(union bpf_attr *attr)
{
	int numa_node = bpf_map_attr_numa_node(attr);
	size_t size, elem_size = 0;
	struct bpf_pifo_map *pifo;
	u32 range;
	int err;

	if (!capable(CAP_NET_ADMIN))
		return ERR_PTR(-EPERM);

	if ((attr->map_type == BPF_MAP_TYPE_PIFO_XDP && attr->value_size != 4) ||
	    attr->key_size != 4 || attr->map_extra & ~0xFFFFFFFFULL ||
	    attr->map_flags & ~PIFO_CREATE_FLAG_MASK)
		return ERR_PTR(-EINVAL);

	range = attr->map_extra;
	if (!range || !is_power_of_2(range))
		return ERR_PTR(-EINVAL);

	if (attr->map_type == BPF_MAP_TYPE_PIFO_GENERIC) {
		elem_size = (attr->value_size + sizeof(struct bpf_pifo_element));
		if (elem_size > U32_MAX / attr->max_entries)
			return ERR_PTR(-E2BIG);
	}

	size = sizeof(*pifo) + attr->max_entries * elem_size;
	pifo = bpf_map_area_alloc(size, numa_node);
	if (!pifo)
		return ERR_PTR(-ENOMEM);

	err = pifo_map_init_map(pifo, attr, elem_size, range);
	if (err) {
		bpf_map_area_free(pifo);
		return ERR_PTR(err);
	}

	spin_lock_init(&pifo->lock);
	return &pifo->map;
}

static void pifo_queue_flush(struct bpf_pifo_queue *queue)
{
#ifdef CONFIG_NET
	unsigned long *bitmap = queue->lvl_bitmap[queue->levels - 1];
	int i = 0;

	/* this is only ever called in the RCU callback when freeing the map, so
	 * no need for locking
	 */
	while (i < queue->range) {
		struct bpf_pifo_bucket *bucket = &queue->buckets[i];
		struct xdp_frame *frame = &bucket->head->frame, *next;

		while (frame) {
			next = frame->next;
			xdp_return_frame(frame);
			frame = next;
		}
		i = find_next_bit(bitmap, queue->range, i + 1);
	}
#endif
}

static void pifo_map_free(struct bpf_map *map)
{
	struct bpf_pifo_map *pifo = container_of(map, struct bpf_pifo_map, map);

	/* At this point bpf_prog->aux->refcnt == 0 and this map->refcnt == 0,
	 * so the programs (can be more than one that used this map) were
	 * disconnected from events. The following synchronize_rcu() guarantees
	 * both rcu read critical sections complete and waits for
	 * preempt-disable regions (NAPI being the relevant context here) so we
	 * are certain there will be no further reads against the netdev_map and
	 * all flush operations are complete. Flush operations can only be done
	 * from NAPI context for this reason.
	 */

	synchronize_rcu();

	if (map->map_type == BPF_MAP_TYPE_PIFO_XDP) {
		pifo_queue_flush(pifo->q_primary);
		pifo_queue_flush(pifo->q_secondary);
	}
	pifo_queue_free(pifo->q_primary);
	pifo_queue_free(pifo->q_secondary);
	bpf_map_area_free(pifo->elem_cache);
	bpf_map_area_free(pifo);
}

static int pifo_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	struct bpf_pifo_map *pifo = container_of(map, struct bpf_pifo_map, map);
	u32 index = key ? *(u32 *)key : U32_MAX, offset;
	struct bpf_pifo_queue *queue = pifo->q_primary;
	unsigned long idx, flags;
	u32 *next = next_key;
	int ret = -ENOENT;

	spin_lock_irqsave(&pifo->lock, flags);

	if (index == U32_MAX || index < queue->min_rank)
		offset = 0;
	else
		offset = index - queue->min_rank + 1;

	if (offset >= queue->range) {
		offset -= queue->range;
		queue = pifo->q_secondary;

		if (offset >= queue->range)
			goto out;
	}

search:
	idx = find_next_bit(queue->lvl_bitmap[queue->levels - 1],
			    queue->range, offset);
	if (idx == queue->range) {
		if (queue == pifo->q_primary) {
			queue = pifo->q_secondary;
			offset = 0;
			goto search;
		}
		goto out;
	}

	*next = idx + queue->min_rank;
	ret = 0;
out:
	spin_unlock_irqrestore(&pifo->lock, flags);
	return ret;
}

static void pifo_set_bit(struct bpf_pifo_queue *queue, u32 rank)
{
	u32 i;

	for (i = queue->levels; i > 0; i--) {
		unsigned long *bitmap = queue->lvl_bitmap[i - 1];

		set_bit(rank, bitmap);
		rank /= BITS_PER_TYPE(long);
	}
}

static void pifo_clear_bit(struct bpf_pifo_queue *queue, u32 rank)
{
	u32 i;

	for (i = queue->levels; i > 0; i--) {
		unsigned long *bitmap = queue->lvl_bitmap[i - 1];

		clear_bit(rank, bitmap);
		rank /= BITS_PER_TYPE(long);

		// another bit is set in this word, don't clear bit in higher
		// level
		if (*(bitmap + rank))
			break;
	}
}

static void pifo_item_set_next(union bpf_pifo_item *item, void *next, bool xdp)
{
	if (xdp)
		item->frame.next = next;
	else
		item->elem.next = next;
}

static int __pifo_map_enqueue(struct bpf_pifo_map *pifo, union bpf_pifo_item *item,
			      u64 rank, bool xdp)
{
	struct bpf_pifo_queue *queue = pifo->q_primary;
	struct bpf_pifo_bucket *bucket;
	u64 q_index;

	lockdep_assert_held(&pifo->lock);

	if (unlikely(pifo_map_is_full(pifo)))
		return -EOVERFLOW;

	if (rank < queue->min_rank)
		return -ERANGE;

	pifo_item_set_next(item, NULL, xdp);

	q_index = rank - queue->min_rank;
	if (unlikely(q_index >= queue->range)) {
		/* If we overflow the primary queue, enqueue into secondary, and
		 * if we overflow that enqueue as the last item
		 */
		q_index -= queue->range;
		queue = pifo->q_secondary;

		if (q_index >= queue->range)
			q_index = queue->range - 1;
	}

	bucket = &queue->buckets[q_index];
	if (likely(!bucket->head)) {
		bucket->head = item;
		bucket->tail = item;
		pifo_set_bit(queue, q_index);
	} else {
		pifo_item_set_next(bucket->tail, item, xdp);
		bucket->tail = item;
	}

	pifo->num_queued++;
	bucket->elem_count++;
	return 0;
}

int pifo_map_enqueue(struct bpf_map *map, struct xdp_frame *xdpf, u32 index)
{
	struct bpf_pifo_map *pifo = container_of(map, struct bpf_pifo_map, map);
	int ret;

	/* called under local_bh_disable() so no need to use irqsave variant */
	spin_lock(&pifo->lock);
	ret = __pifo_map_enqueue(pifo, (union bpf_pifo_item *)xdpf, index, true);
	spin_unlock(&pifo->lock);

	return ret;
}

static unsigned long pifo_find_first_bucket(struct bpf_pifo_queue *queue)
{
	unsigned long *bitmap, bit = 0, offset = 0;
	int i;

	for (i = 0; i < queue->levels; i++) {
		bitmap = queue->lvl_bitmap[i] + offset;
		if (!*bitmap)
			return -1;
		bit = __ffs(*bitmap);
		offset = offset * BITS_PER_TYPE(long) + bit;
	}
	return offset;
}

static union bpf_pifo_item *__pifo_map_dequeue(struct bpf_pifo_map *pifo,
					       u64 flags, u64 *rank, bool xdp)
{
	struct bpf_pifo_queue *queue = pifo->q_primary;
	struct bpf_pifo_bucket *bucket;
	union bpf_pifo_item *item;
	unsigned long bucket_idx;

	lockdep_assert_held(&pifo->lock);

	if (flags) {
		*rank = -EINVAL;
		return NULL;
	}

	if (!pifo->num_queued) {
		*rank = -ENOENT;
		return NULL;
	}

	if (unlikely(pifo_queue_is_empty(queue))) {
		swap(pifo->q_primary, pifo->q_secondary);
		pifo->q_secondary->min_rank = pifo->q_primary->min_rank + pifo->q_primary->range;
		queue = pifo->q_primary;
	}

	bucket_idx = pifo_find_first_bucket(queue);
	if (bucket_idx == -1) {
		*rank = -ENOENT;
		return NULL;
	}
	bucket = &queue->buckets[bucket_idx];

	if (WARN_ON_ONCE(!bucket->tail)) {
		*rank = -EFAULT;
		return NULL;
	}

	item = bucket->head;
	if (xdp)
		bucket->head = (union bpf_pifo_item *)item->frame.next;
	else
		bucket->head = (union bpf_pifo_item *)item->elem.next;

	if (!bucket->head) {
		bucket->tail = NULL;
		pifo_clear_bit(queue, bucket_idx);
	}
	pifo->num_queued--;
	bucket->elem_count--;

	*rank = bucket_idx + queue->min_rank;
	return item;
}

struct xdp_frame *pifo_map_dequeue(struct bpf_map *map, u64 flags, u64 *rank)
{
	struct bpf_pifo_map *pifo = container_of(map, struct bpf_pifo_map, map);
	union bpf_pifo_item *item;
	unsigned long lflags;

	spin_lock_irqsave(&pifo->lock, lflags);
	item = __pifo_map_dequeue(pifo, flags, rank, true);
	spin_unlock_irqrestore(&pifo->lock, lflags);

	return item ? &item->frame : NULL;
}

static void *pifo_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_pifo_map *pifo = container_of(map, struct bpf_pifo_map, map);
	struct bpf_pifo_queue *queue = pifo->q_primary;
	struct bpf_pifo_bucket *bucket;
	u32 rank =  *(u32 *)key, idx;

	if (rank < queue->min_rank)
		return NULL;

	idx = rank - queue->min_rank;
	if (idx >= queue->range) {
		idx -= queue->range;
		queue = pifo->q_secondary;

		if (idx >= queue->range)
			return NULL;
	}

	bucket = &queue->buckets[idx];
	/* FIXME: what happens if this changes while userspace is reading the
	 * value
	 */
	return &bucket->elem_count;
}

static int pifo_map_push_elem(struct bpf_map *map, void *value, u64 flags)
{
	struct bpf_pifo_map *pifo = container_of(map, struct bpf_pifo_map, map);
	struct bpf_pifo_element *dst;
	unsigned long irq_flags;
	u64 prio;
	int ret;

	/* Check if any of the actual flag bits are set */
	if (flags & ~BPF_PIFO_PRIO_MASK)
		return -EINVAL;

	prio = flags & BPF_PIFO_PRIO_MASK;

	spin_lock_irqsave(&pifo->lock, irq_flags);

	dst = elem_cache_get(pifo->elem_cache);
	if (!dst) {
		ret = -EOVERFLOW;
		goto out;
	}

	memcpy(&dst->data, value, pifo->map.value_size);

	ret = __pifo_map_enqueue(pifo, (union bpf_pifo_item *)dst, prio, false);
	if (ret)
		elem_cache_put(pifo->elem_cache, dst);

out:
	spin_unlock_irqrestore(&pifo->lock, irq_flags);
	return ret;
}

static int pifo_map_pop_elem(struct bpf_map *map, void *value)
{
	struct bpf_pifo_map *pifo = container_of(map, struct bpf_pifo_map, map);
	union bpf_pifo_item *item;
	unsigned long flags;
	int err = 0;
	u64 rank;

	spin_lock_irqsave(&pifo->lock, flags);

	item = __pifo_map_dequeue(pifo, 0, &rank, false);
	if (!item) {
		err = rank;
		goto out;
	}

	memcpy(value, &item->elem.data, pifo->map.value_size);
	elem_cache_put(pifo->elem_cache, &item->elem);

out:
	spin_unlock_irqrestore(&pifo->lock, flags);
	return err;
}

static int pifo_map_update_elem(struct bpf_map *map, void *key, void *value,
				u64 map_flags)
{
	return -EINVAL;
}

static int pifo_map_delete_elem(struct bpf_map *map, void *key)
{
	return -EINVAL;
}

static int pifo_map_peek_elem(struct bpf_map *map, void *value)
{
	return -EINVAL;
}

static int pifo_map_redirect(struct bpf_map *map, u64 index, u64 flags)
{
#ifdef CONFIG_NET
	struct bpf_redirect_info *ri = this_cpu_ptr(&bpf_redirect_info);
	const u64 action_mask = XDP_ABORTED | XDP_DROP | XDP_PASS | XDP_TX;

	/* Lower bits of the flags are used as return code on lookup failure */
	if (unlikely(flags & ~action_mask))
		return XDP_ABORTED;

	ri->tgt_value = NULL;
	ri->tgt_index = index;
	ri->map_id = map->id;
	ri->map_type = map->map_type;
	ri->flags = flags;
	WRITE_ONCE(ri->map, map);
	return XDP_REDIRECT;
#else
	return XDP_ABORTED;
#endif
}

BTF_ID_LIST_SINGLE(pifo_xdp_map_btf_ids, struct, bpf_pifo_map);
const struct bpf_map_ops pifo_xdp_map_ops = {
	.map_meta_equal = bpf_map_meta_equal,
	.map_alloc = pifo_map_alloc,
	.map_free = pifo_map_free,
	.map_get_next_key = pifo_map_get_next_key,
	.map_lookup_elem = pifo_map_lookup_elem,
	.map_update_elem = pifo_map_update_elem,
	.map_delete_elem = pifo_map_delete_elem,
	.map_check_btf = map_check_no_btf,
	.map_btf_id = &pifo_xdp_map_btf_ids[0],
	.map_redirect = pifo_map_redirect,
};

BTF_ID_LIST_SINGLE(pifo_generic_map_btf_ids, struct, bpf_pifo_map);
const struct bpf_map_ops pifo_generic_map_ops = {
	.map_meta_equal = bpf_map_meta_equal,
	.map_alloc = pifo_map_alloc,
	.map_free = pifo_map_free,
	.map_get_next_key = pifo_map_get_next_key,
	.map_lookup_elem = pifo_map_lookup_elem,
	.map_update_elem = pifo_map_update_elem,
	.map_delete_elem = pifo_map_delete_elem,
	.map_push_elem = pifo_map_push_elem,
	.map_pop_elem = pifo_map_pop_elem,
	.map_peek_elem = pifo_map_peek_elem,
	.map_check_btf = map_check_no_btf,
	.map_btf_id = &pifo_generic_map_btf_ids[0],
};
