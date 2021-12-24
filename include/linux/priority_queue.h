// SPDX-License-Identifier: GPL-2.0
/*
 *  A priority queue implementation based on rbtree
 *
 *   Copyright (C) 2021, Bytedance, Cong Wang <cong.wang@bytedance.com>
 */

#ifndef	_LINUX_PRIORITY_QUEUE_H
#define	_LINUX_PRIORITY_QUEUE_H

#include <linux/rbtree.h>

struct pq_node {
	struct rb_node rb_node;
};

struct pq_root {
	struct rb_root_cached rb_root;
	bool (*cmp)(struct pq_node *l, struct pq_node *r);
};

static inline void pq_root_init(struct pq_root *root,
				bool (*cmp)(struct pq_node *l, struct pq_node *r))
{
	root->rb_root = RB_ROOT_CACHED;
	root->cmp = cmp;
}

static inline void pq_push(struct pq_root *root, struct pq_node *node)
{
	struct rb_node **link = &root->rb_root.rb_root.rb_node;
	struct rb_node *parent = NULL;
	struct pq_node *entry;
	bool leftmost = true;

	/*
	 * Find the right place in the rbtree:
	 */
	while (*link) {
		parent = *link;
		entry = rb_entry(parent, struct pq_node, rb_node);
		/*
		 * We dont care about collisions. Nodes with
		 * the same key stay together.
		 */
		if (root->cmp(entry, node)) {
			link = &parent->rb_left;
		} else {
			link = &parent->rb_right;
			leftmost = false;
		}
	}

	rb_link_node(&node->rb_node, parent, link);
	rb_insert_color_cached(&node->rb_node, &root->rb_root, leftmost);
}

static inline struct pq_node *pq_top(struct pq_root *root)
{
	struct rb_node *left = rb_first_cached(&root->rb_root);

	if (!left)
		return NULL;
	return rb_entry(left, struct pq_node, rb_node);
}

static inline struct pq_node *pq_pop(struct pq_root *root)
{
	struct pq_node *t = pq_top(root);

	if (t)
		rb_erase_cached(&t->rb_node, &root->rb_root);
	return t;
}

static inline void pq_flush(struct pq_root *root, void (*destroy)(struct pq_node *))
{
	struct rb_node *node, *next;

	for (node = rb_first(&root->rb_root.rb_root);
	     next = node ? rb_next(node) : NULL, node != NULL;
	     node = next) {
		struct pq_node *pqe;

		pqe = rb_entry(node, struct pq_node, rb_node);
		if (destroy)
			destroy(pqe);
	}
}
#endif	/* _LINUX_PRIORITY_QUEUE_H */
