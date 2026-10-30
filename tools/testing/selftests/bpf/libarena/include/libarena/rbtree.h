/* SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause */

#pragma once

#define RB_MAXLVL_PRINT (16)

/* Cache line size assumed for keeping the lockless fields apart. */
#define RB_CACHELINE_SIZE (64)

struct rbnode;

struct rbnode {
	struct rbnode __arena *parent;
	union {
		struct {
			struct rbnode __arena *left;
			struct rbnode __arena *right;
		};

		struct rbnode __arena *child[2];
	};
	uint64_t key;
	/* Used as a linked list or to store KV pairs. */
	union {
		struct rbnode __arena *next;
		uint64_t value;
	};
	bool is_red;
};

/*
 * Does the rbtree allocate its own nodes, or do they get
 * allocated by the caller?
 */
enum rbtree_alloc {
	RB_ALLOC,
	RB_NOALLOC,
};

/*
 * Specify the behavior of rbtree insertions when the key is
 * already present in the tree.
 *
 * RB_DEFAULT: Default behavior, reject the new insert.
 *
 * RB_UPDATE: Update the existing value in the rbtree.
 * This updates the node itself, not just the value in
 * the existing node.
 *
 * RB_DUPLICATE: Allow nodes with identical keys in the rbtree.
 * Nodes with identical keys are kept in insertion order, so
 * rb_least() and rb_pop() return the oldest of them. Finding
 * or removing by key acts on any of them.
 */
enum rbtree_insert_mode {
	RB_DEFAULT,
	RB_UPDATE,
	RB_DUPLICATE,
};

struct rbtree {
	/* Writer fields, on a cache line of their own. */
	struct rbnode __arena *root;
	enum rbtree_alloc alloc;
	enum rbtree_insert_mode insert;

	/*
	 * The leftmost node and the node count on their own cache line.
	 * The writer keeps them current, and readers may read them without
	 * the writer's lock (see rb_first() and friends).
	 */
	struct {
		struct rbnode __arena *first;
		uint64_t nr;
	} __attribute__((aligned(RB_CACHELINE_SIZE)));
};

#ifdef __BPF__
struct rbtree __arena *rb_create(enum rbtree_alloc alloc, enum rbtree_insert_mode insert);

/*
 * Initialize and finalize a tree embedded in another arena object.
 * rb_fini() frees the nodes of an RB_ALLOC tree and fails with -EBUSY on a
 * non-empty RB_NOALLOC tree. It leaves the tree's memory to its owner.
 */
int rb_init(struct rbtree __arena *rbtree, enum rbtree_alloc alloc,
	    enum rbtree_insert_mode insert);
int rb_fini(struct rbtree __arena *rbtree);

int rb_destroy(struct rbtree __arena *rbtree);
int rb_insert(struct rbtree __arena *rbtree, u64 key, u64 value);
int rb_remove(struct rbtree __arena *rbtree, u64 key);
int rb_find(struct rbtree __arena *rbtree, u64 key, u64 *value);
int rb_print(struct rbtree __arena *rbtree);
int rb_least(struct rbtree __arena *rbtree, u64 *key, u64 *value);
int rb_pop(struct rbtree __arena *rbtree, u64 *key, u64 *value);

int rb_insert_node(struct rbtree __arena *rbtree, struct rbnode __arena *node);
int rb_remove_node(struct rbtree __arena *rbtree, struct rbnode __arena *node);

struct rbnode __arena *rb_node_alloc(u64 key, u64 value);
void rb_node_free(struct rbnode __arena *rbnode);

int rb_integrity_check(struct rbtree __arena *rbtree);

/*
 * Return the in-order successor of @node, or NULL if @node is the last one.
 * Walking from rb_first() with it visits the tree in key order, equal keys in
 * insertion order. Call it under the writer's lock.
 */
static __always_inline struct rbnode __arena *rb_next(struct rbnode __arena *node)
{
	struct rbnode __arena *parent;

	if (node->right) {
		node = node->right;
		while (node->left && can_loop)
			node = node->left;
		return node;
	}

	/* Climb until we leave a left subtree; its parent comes next. */
	while ((parent = node->parent) && node == parent->right && can_loop)
		node = parent;

	return parent;
}

/*
 * Lockless reads of the head and the node count. They need not be called
 * under the writer's lock, so they are advisory: the tree may change before
 * the caller acts on the result. The node rb_first() returns may have
 * left the tree, or been freed in an RB_ALLOC tree, by the time the
 * caller reads it. The count is a separate read and need not agree
 * with the head.
 */
static __always_inline struct rbnode __arena *rb_first(struct rbtree __arena *rbtree)
{
	return READ_ONCE(rbtree->first);
}

/* -ENOENT if the tree is empty, 0 with the leftmost key in @key otherwise. */
static __always_inline int rb_first_key(struct rbtree __arena *rbtree, u64 *key)
{
	struct rbnode __arena *first = READ_ONCE(rbtree->first);

	if (!first)
		return -ENOENT;

	*key = READ_ONCE(first->key);
	return 0;
}

static __always_inline u64 rb_nr_nodes(struct rbtree __arena *rbtree)
{
	return READ_ONCE(rbtree->nr);
}

#endif /* __BPF__ */
