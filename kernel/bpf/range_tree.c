// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */
#include <linux/interval_tree_generic.h>
#include <linux/slab.h>
#include <linux/bpf.h>
#include "range_tree.h"

/*
 * struct range_tree is a data structure used to allocate contiguous memory
 * ranges in bpf arena. It's a large bitmap. The contiguous sequence of bits is
 * represented by struct range_node or 'rn' for short.
 * rn->rn_rbnode links it into an interval tree while
 * rn->rb_range_size links it into a second rbtree sorted by size of the range.
 * __find_range() performs binary search and best fit algorithm to find the
 * range less or equal requested size.
 * range_tree_clear/set() clears or sets a range of bits in this bitmap. The
 * adjacent ranges are merged or split at the same time.
 *
 * The split/merge logic is based/borrowed from XFS's xbitmap32 added
 * in commit 6772fcc8890a ("xfs: convert xbitmap to interval tree").
 *
 * The implementation relies on external lock to protect rbtree-s.
 * The alloc/free of range_node-s is done via kmalloc_nolock().
 *
 * bpf arena is using range_tree to represent unallocated slots.
 * At init time:
 *   range_tree_set(rt, 0, max);
 * Then:
 *   start = range_tree_find(rt, len);
 *   if (start >= 0)
 *     range_tree_clear(rt, start, len);
 * to find free range and mark slots as allocated and later:
 *   range_tree_set(rt, start, len);
 * to mark as unallocated after use.
 */
struct range_node {
	struct rb_node rn_rbnode;
	struct rb_node rb_range_size;
	u32 rn_start;
	u32 rn_last; /* inclusive */
	u32 __rn_subtree_last;
	bool available; /* range is available for allocating. */
};

/* Is the range available for merging? */
static inline bool range_available(struct range_node *rn)
{
	return rn && rn->available;
}

static struct range_node *rb_to_range_node(struct rb_node *rb)
{
	return rb_entry(rb, struct range_node, rb_range_size);
}

static u32 rn_size(struct range_node *rn)
{
	return rn->rn_last - rn->rn_start + 1;
}

/* Find range that fits best to requested size */
static inline struct range_node *__find_range(struct range_tree *rt, u32 len)
{
	struct rb_node *rb = rt->range_size_root.rb_root.rb_node;
	struct rb_node *best = NULL;
	struct range_node *rn;

	while (rb) {
		rn = rb_to_range_node(rb);

		if (len <= rn_size(rn)) {
			best = rb;
			rb = rb->rb_right;
		} else {
			rb = rb->rb_left;
		}
	}

	/* Filter unavailable ranges. */
	while (best) {
		rn = rb_to_range_node(best);
		if (range_available(rn))
			return rn;

		best = rb_prev(best);
	}

	return NULL;
}

s64 range_tree_find(struct range_tree *rt, u32 len)
{
	struct range_node *rn;

	rn = __find_range(rt, len);
	if (!rn)
		return -ENOENT;
	return rn->rn_start;
}

/* Insert the range into rbtree sorted by the range size */
static inline void __range_size_insert(struct range_node *rn,
				       struct rb_root_cached *root)
{
	struct rb_node **link = &root->rb_root.rb_node, *rb = NULL;
	u64 size = rn_size(rn);
	bool leftmost = true;

	while (*link) {
		rb = *link;
		if (size > rn_size(rb_to_range_node(rb))) {
			link = &rb->rb_left;
		} else {
			link = &rb->rb_right;
			leftmost = false;
		}
	}

	rb_link_node(&rn->rb_range_size, rb, link);
	rb_insert_color_cached(&rn->rb_range_size, root, leftmost);
}

#define START(node) ((node)->rn_start)
#define LAST(node)  ((node)->rn_last)

INTERVAL_TREE_DEFINE(struct range_node, rn_rbnode, u32,
		     __rn_subtree_last, START, LAST,
		     static inline __maybe_unused,
		     __range_it)

static inline __maybe_unused void
range_it_insert(struct range_node *rn, struct range_tree *rt)
{
	__range_size_insert(rn, &rt->range_size_root);
	__range_it_insert(rn, &rt->it_root);
}

static inline __maybe_unused void
range_it_remove(struct range_node *rn, struct range_tree *rt)
{
	rb_erase_cached(&rn->rb_range_size, &rt->range_size_root);
	RB_CLEAR_NODE(&rn->rb_range_size);
	__range_it_remove(rn, &rt->it_root);
}

static inline __maybe_unused struct range_node *
range_it_iter_first(struct range_tree *rt, u32 start, u32 last)
{
	return __range_it_iter_first(&rt->it_root, start, last);
}

/* Clear the range in this range tree */
int range_tree_clear(struct range_tree *rt, u32 start, u32 len)
{
	u32 first = start;
	u32 last = start + len - 1;
	struct range_node *new_rn;
	struct range_node *rn;

	/* Scan for unavailable ranges and try again if so. */
	while ((rn = range_it_iter_first(rt, first, last))) {
		if (!range_available(rn))
			return -EAGAIN;

		first = rn->rn_last + 1;
	}

	while ((rn = range_it_iter_first(rt, start, last))) {
		if (rn->rn_start < start && rn->rn_last > last) {
			u32 old_last = rn->rn_last;

			/* Overlaps with the entire clearing range */
			range_it_remove(rn, rt);
			rn->rn_last = start - 1;
			range_it_insert(rn, rt);

			/* Add a range */
			new_rn = kmalloc_nolock(sizeof(struct range_node), __GFP_ACCOUNT,
						NUMA_NO_NODE);
			if (!new_rn)
				return -ENOMEM;
			new_rn->available = rn->available;
			new_rn->rn_start = last + 1;
			new_rn->rn_last = old_last;
			range_it_insert(new_rn, rt);
		} else if (rn->rn_start < start) {
			/* Overlaps with the left side of the clearing range */
			range_it_remove(rn, rt);
			rn->rn_last = start - 1;
			range_it_insert(rn, rt);
		} else if (rn->rn_last > last) {
			/* Overlaps with the right side of the clearing range */
			range_it_remove(rn, rt);
			rn->rn_start = last + 1;
			range_it_insert(rn, rt);
			break;
		} else {
			/* in the middle of the clearing range */
			range_it_remove(rn, rt);
			kfree_nolock(rn);
		}
	}
	return 0;
}

/* Is the whole range set ? */
int is_range_tree_set(struct range_tree *rt, u32 start, u32 len)
{
	u32 last = start + len - 1;
	struct range_node *rn;

	for (rn = range_it_iter_first(rt, start, last); rn;
			rn = __range_it_iter_next(rn, start, last)) {
		/* Make sure the range covers the start */
		if (rn->rn_start > start)
			return -ESRCH;

		/* If it covers the entire range we're done. */
		if (rn->rn_last >= last)
			return 0;

		start = rn->rn_last + 1;
	}

	/* No range to cover [start, last] */
	return -ESRCH;
}

/* Do we have adjacent ranges (and do not overlap with them)? */
static int range_get_adjacent(struct range_tree *rt, u32 start, u32 last,
		struct range_node **leftp, struct range_node **rightp)
{
	struct range_node *right;
	struct range_node *left;

	/* Do we have a left-adjacent range ? */
	left = range_it_iter_first(rt, start - 1, start - 1);
	if (left && left->rn_last + 1 != start)
		return -EFAULT;

	/* Do we have a right-adjacent range ? */
	right = range_it_iter_first(rt, last + 1, last + 1);
	if (right && right->rn_start != last + 1)
		return -EFAULT;

	*leftp = left;
	*rightp = right;

	return 0;
}

/*
 * Merge with adjacent available ranges if possible. The new [start, last]
 * has already been confirmed to be adjacent with left/right by the caller.
 */
static int range_tree_merge(struct range_tree *rt, u32 start, u32 last,
		struct range_node *left, struct range_node *right)
{
	if (range_available(left) && range_available(right)) {
		/* Combine left and right adjacent ranges */
		range_it_remove(left, rt);
		range_it_remove(right, rt);
		left->rn_last = right->rn_last;
		range_it_insert(left, rt);
		kfree_nolock(right);
	} else if (range_available(left)) {
		/* Combine with the left range */
		range_it_remove(left, rt);
		left->rn_last = last;
		range_it_insert(left, rt);
	} else if (range_available(right)) {
		/* Combine with the right range */
		range_it_remove(right, rt);
		right->rn_start = start;
		range_it_insert(right, rt);
	} else {
		/* No merge available. */
		return -ENOENT;
	}

	return 0;
}

/* Make a range available, possibly merging. */
int range_tree_make_avail(struct range_tree *rt, u32 start, u32 len)
{
	u32 last = start + len - 1;
	struct range_node *rn;
	struct range_node *right;
	struct range_node *left;
	int err;

	/*
	 * Confirm the range exists is unavailable,
	 * and fits the requested range exactly.
	 */
	rn = range_it_iter_first(rt, start, last);
	if (!rn || rn->available)
		return -EINVAL;

	if (rn->rn_start != start || rn->rn_last != last)
		return -EINVAL;

	err = range_get_adjacent(rt, start, last, &left, &right);
	if (err)
		return err;

	/* If no merging required, just make available. */
	if (!range_available(left) && !range_available(right)) {
		rn->available = true;
		return 0;
	}

	/* Can merge, remove the range already. */
	start = rn->rn_start;
	last = rn->rn_last;
	range_it_remove(rn, rt);
	kfree_nolock(rn);

	return range_tree_merge(rt, start, last, left, right);
}

/* Set the range in this range tree */
static int range_tree_set(struct range_tree *rt, u32 start, u32 len, bool available)
{
	u32 last = start + len - 1;
	struct range_node *right;
	struct range_node *left;
	int err;

	/* Is this whole range already set ? */
	left = range_it_iter_first(rt, start, last);
	if (left && left->rn_start <= start && left->rn_last >= last &&
	    range_available(left) && available)
		return 0;

	/* Clear out everything in the range we want to set. */
	err = range_tree_clear(rt, start, len);
	if (err)
		return err;

	/* Get adjacent ranges and check for overlaps. */
	err = range_get_adjacent(rt, start, last, &left, &right);
	if (err)
		return err;

	/*
	 * If the range is not available for allocation, don't merge.
	 * Unavailable ranges are in the process of being freed and should
	 * be imminently marked available, so merging them with other
	 * unavailable ranges will just lead to splitting the range back
	 * almost immediately.
	 */
	if (available) {
		err = range_tree_merge(rt, start, last, left, right);
		if (!err)
			return 0;
	}

	left = kmalloc_nolock(sizeof(struct range_node), __GFP_ACCOUNT, NUMA_NO_NODE);
	if (!left)
		return -ENOMEM;
	left->available = available;
	left->rn_start = start;
	left->rn_last = last;
	range_it_insert(left, rt);

	return 0;
}

int range_tree_set_avail(struct range_tree *rt, u32 start, u32 len)
{
	return range_tree_set(rt, start, len, true);
}

int range_tree_set_unavail(struct range_tree *rt, u32 start, u32 len)
{
	return range_tree_set(rt, start, len, false);
}

void range_tree_destroy(struct range_tree *rt)
{
	struct range_node *rn;

	while ((rn = range_it_iter_first(rt, 0, -1U))) {
		range_it_remove(rn, rt);
		kfree_nolock(rn);
	}
}

void range_tree_init(struct range_tree *rt)
{
	rt->it_root = RB_ROOT_CACHED;
	rt->range_size_root = RB_ROOT_CACHED;
}
