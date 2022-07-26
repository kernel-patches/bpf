// SPDX-License-Identifier: GPL-2.0-only
/*
 * Derived from qp.c in https://github.com/fanf2/qp.git
 *
 * Copyright (C) 2022. Huawei Technologies Co., Ltd
 */
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>

/* qp-trie (quadbit popcount trie) is a memory efficient trie. Unlike
 * normal trie which uses byte as lookup key, qp-trie interprets its keys
 * as quadbit/nibble array and uses one nibble each time during lookup.
 * The most significant nibble (upper nibble) of byte N in the key will
 * be the 2*N element of nibble array, and the least significant nibble
 * (lower nibble) of byte N will be the 2*N+1 element in nibble array.
 *
 * For normal trie, it may have 256 child nodes, and for qp-trie one branch
 * node may have 17 child nodes. #0 child node is special because it must
 * be a leaf node and its key is the same as the branch node. #1~#16 child
 * nodes represent leaf nodes or branch nodes which have different keys
 * with parent node. The key of branch node is the common prefix for these
 * child nodes, and the index of child node minus one is the value of first
 * different nibble between these child nodes.
 *
 * qp-trie reduces memory usage through two methods:
 * (1) Branch node doesn't store the key. It only stores the position of
 *     the first nibble which differentiates child nodes.
 * (2) Branch node doesn't store all 17 child nodes. It uses a bitmap and
 *     popcount() to implement a sparse array and only allocates memory
 *     for those present children.
 *
 * Like normal trie, qp-trie is also ordered and is in big-endian
 * lexicographic order. If traverse qp-trie in a depth-first way, it will
 * return a string of ordered keys.
 *
 * The following diagrams show the construction of a tiny qp-trie:
 *
 * (1) insert abc
 *
 *          [ leaf node: abc ]
 *
 * (2) insert abc_d
 *
 * The first different nibble between "abc" and "abc_d" is the upper nibble
 * of character '_' (0x5), and its position in nibble array is 6
 * (starts from 0).
 *
 *          [ branch node ] bitmap: 0x41 diff pos: 6
 *                 |
 *                 *
 *             children
 *          [0]        [6]
 *           |          |
 *       [leaf: abc] [leaf: abc_d]
 *
 * (3) insert abc_e
 *
 * The first different nibble between "abc_d" and "abc_e" is the lower
 * nibble of character 'd'/'e', and its position in array is 9.
 *
 *          [ branch node ] bitmap: 0x41 diff pos: 6
 *                 |
 *                 *
 *             children
 *          [0]        [6]
 *           |          |
 *       [leaf: abc]    |
 *                      *
 *                [ branch node ] bitmap: 0x60 diff pos: 9
 *                      |
 *                      *
 *                   children
 *                [5]        [6]
 *                 |          |
 *          [leaf: abc_d]  [leaf: abc_e]
 */

#define QP_TRIE_CREATE_FLAG_MASK (BPF_F_NO_PREALLOC | BPF_F_NUMA_NODE | \
				  BPF_F_ACCESS_MASK)

/* bit[0] of nodes in qp_trie_branch is used to tell node type:
 *
 * bit[0]: 0-branch node
 * bit[0]: 1-leaf node
 *
 * Size of qp_trie_branch is already 2-bytes aligned, so only need to make
 * allocation of leaf node to be 2-bytes aligned.
 */
#define QP_TRIE_LEAF_NODE_MASK 1UL
#define QP_TRIE_LEAF_ALLOC_ALIGN 2

/* To reduce memory usage, only qp_trie_branch is RCU-freed. To handle
 * freeing of the last leaf node, an extra qp_trie_branch node is
 * allocated. The branch node has only one child and its index is 0. It
 * is set as root node after adding the first leaf node.
 */
#define QP_TRIE_ROOT_NODE_INDEX 0
#define QP_TRIE_NON_ROOT_NODE_MASK 1

#define QP_TRIE_NIBBLE_SHIFT 1
#define QP_TRIE_BYTE_INDEX_SHIFT 2

#define QP_TRIE_MIN_KEY_DATA_SIZE 1
#define QP_TRIE_MAX_KEY_DATA_SIZE (1U << 30)
#define QP_TRIE_MIN_KEY_SIZE (sizeof(struct bpf_qp_trie_key) + QP_TRIE_MIN_KEY_DATA_SIZE)
#define QP_TRIE_MAX_KEY_SIZE (sizeof(struct bpf_qp_trie_key) + QP_TRIE_MAX_KEY_DATA_SIZE)

#define QP_TRIE_TWIGS_FREE_NONE_IDX 17

struct qp_trie_branch {
	/* The bottom two bits of index are used as special flags:
	 *
	 * bit[0]: 0-root, 1-not root
	 * bit[1]: 0-upper nibble, 1-lower nibble
	 *
	 * bit[2:31]: byte index for key
	 */
	unsigned int index;
	/* 17 bits are used to accommodate arbitrary keys, even when there are
	 * zero-bytes in these keys.
	 *
	 * bit[0]: a leaf node has the same key as the prefix of parent node
	 * bit[N]: a child node with the value of nibble at index as (N - 1)
	 */
	unsigned int bitmap:17;
	/* The index of leaf node will be RCU-freed together */
	unsigned int to_free_idx:5;
	struct qp_trie_branch __rcu *parent;
	struct rcu_head rcu;
	void __rcu *nodes[0];
};

#define QP_TRIE_NR_SUBTREE 256

struct qp_trie {
	struct bpf_map map;
	atomic_t entries;
	void __rcu *roots[QP_TRIE_NR_SUBTREE];
	spinlock_t locks[QP_TRIE_NR_SUBTREE];
};

struct qp_trie_diff {
	unsigned int index;
	unsigned int sibling_bm;
	unsigned int new_bm;
};

static inline bool is_valid_key_data_len(const struct bpf_qp_trie_key *key,
					 unsigned int key_size)
{
	return key->len >= QP_TRIE_MIN_KEY_DATA_SIZE &&
	       key->len <= key_size - sizeof(*key);
}

static inline void *to_child_node(struct bpf_qp_trie_key *key)
{
	return (void *)((long)key | QP_TRIE_LEAF_NODE_MASK);
}

static inline struct bpf_qp_trie_key *to_leaf_node(void *node)
{
	return (void *)((long)node & ~QP_TRIE_LEAF_NODE_MASK);
}

static inline bool is_branch_node(void *node)
{
	return !((long)node & QP_TRIE_LEAF_NODE_MASK);
}

static inline bool is_same_key(const struct bpf_qp_trie_key *l, const struct bpf_qp_trie_key *r)
{
	return l->len == r->len && !memcmp(l->data, r->data, r->len);
}

static inline void *qp_trie_leaf_value(const struct bpf_qp_trie_key *key)
{
	return (void *)key + sizeof(*key) + key->len;
}

static inline unsigned int calc_twig_index(unsigned int mask, unsigned int bitmap)
{
	return hweight32(mask & (bitmap - 1));
}

static inline unsigned int calc_twig_nr(unsigned int bitmap)
{
	return hweight32(bitmap);
}

static inline unsigned int nibble_to_bitmap(unsigned char nibble)
{
	return 1U << (nibble + 1);
}

static inline unsigned int index_to_byte_index(unsigned int index)
{
	return index >> QP_TRIE_BYTE_INDEX_SHIFT;
}

static inline unsigned int calc_br_bitmap(unsigned int index, const struct bpf_qp_trie_key *key)
{
	unsigned int byte;
	unsigned char nibble;

	if (index == QP_TRIE_ROOT_NODE_INDEX)
		return 1;

	byte = index_to_byte_index(index);
	if (byte >= key->len)
		return 1;

	nibble = key->data[byte];
	/* lower nibble */
	if ((index >> QP_TRIE_NIBBLE_SHIFT) & 1)
		nibble &= 0xf;
	else
		nibble >>= 4;
	return nibble_to_bitmap(nibble);
}

static void qp_trie_free_twigs_rcu(struct rcu_head *rcu)
{
	struct qp_trie_branch *twigs = container_of(rcu, struct qp_trie_branch, rcu);
	unsigned int idx = twigs->to_free_idx;

	if (idx != QP_TRIE_TWIGS_FREE_NONE_IDX)
		kfree(to_leaf_node(twigs->nodes[idx]));
	kfree(twigs);
}

static void qp_trie_branch_free(struct qp_trie_branch *twigs, unsigned int to_free_idx)
{
	twigs->to_free_idx = to_free_idx;
	call_rcu(&twigs->rcu, qp_trie_free_twigs_rcu);
}

static inline struct qp_trie_branch *
qp_trie_branch_new(struct bpf_map *map, unsigned int nr)
{
	struct qp_trie_branch *a;

	a = bpf_map_kmalloc_node(map, sizeof(*a) + nr * sizeof(*a->nodes),
				 GFP_NOWAIT | __GFP_NOWARN, map->numa_node);
	return a;
}

static inline void qp_trie_assign_parent(struct qp_trie_branch *parent, void *node)
{
	if (is_branch_node(node))
		rcu_assign_pointer(((struct qp_trie_branch *)node)->parent, parent);
}

static void qp_trie_update_parent(struct qp_trie_branch *parent, unsigned int nr)
{
	unsigned int i;

	for (i = 0; i < nr; i++)
		qp_trie_assign_parent(parent, parent->nodes[i]);
}

/* new_node can be either a leaf node or a branch node */
static struct qp_trie_branch *
qp_trie_branch_replace(struct bpf_map *map, struct qp_trie_branch *old, unsigned int bitmap,
		       void *new_node)
{
	unsigned int nr = calc_twig_nr(old->bitmap);
	unsigned int p = calc_twig_index(old->bitmap, bitmap);
	struct qp_trie_branch *twigs;

	twigs = qp_trie_branch_new(map, nr);
	if (!twigs)
		return NULL;

	if (p)
		memcpy(twigs->nodes, old->nodes, p * sizeof(*twigs->nodes));

	rcu_assign_pointer(twigs->nodes[p], new_node);

	if (nr - 1 > p)
		memcpy(&twigs->nodes[p+1], &old->nodes[p+1], (nr - 1 - p) * sizeof(*twigs->nodes));

	twigs->index = old->index;
	twigs->bitmap = old->bitmap;
	/* Initialize parent of upper-level node first,
	 * then update parent for child nodes after parent node is
	 * fully initialized
	 */
	RCU_INIT_POINTER(twigs->parent, old->parent);

	qp_trie_update_parent(twigs, nr);

	return twigs;
}

static struct qp_trie_branch *
qp_trie_branch_insert(struct bpf_map *map, struct qp_trie_branch *old, unsigned int bitmap,
		      struct bpf_qp_trie_key *new)
{
	unsigned int nr = calc_twig_nr(old->bitmap);
	unsigned int p = calc_twig_index(old->bitmap, bitmap);
	struct qp_trie_branch *twigs;

	twigs = qp_trie_branch_new(map, nr + 1);
	if (!twigs)
		return NULL;

	if (p)
		memcpy(twigs->nodes, old->nodes, p * sizeof(*twigs->nodes));

	rcu_assign_pointer(twigs->nodes[p], to_child_node(new));

	if (nr > p)
		memcpy(&twigs->nodes[p+1], &old->nodes[p], (nr - p) * sizeof(*twigs->nodes));

	twigs->bitmap = old->bitmap | bitmap;
	twigs->index = old->index;
	RCU_INIT_POINTER(twigs->parent, old->parent);

	qp_trie_update_parent(twigs, nr + 1);

	return twigs;
}

static struct qp_trie_branch *
qp_trie_branch_remove(struct bpf_map *map, struct qp_trie_branch *old, unsigned int bitmap)
{
	unsigned int nr = calc_twig_nr(old->bitmap);
	unsigned int p = calc_twig_index(old->bitmap, bitmap);
	struct qp_trie_branch *twigs;

	twigs = qp_trie_branch_new(map, nr - 1);
	if (!twigs)
		return NULL;

	if (p)
		memcpy(twigs->nodes, old->nodes, p * sizeof(*twigs->nodes));
	if (nr - 1 > p)
		memcpy(&twigs->nodes[p], &old->nodes[p+1], (nr - 1 - p) * sizeof(*twigs->nodes));

	twigs->bitmap = old->bitmap & ~bitmap;
	twigs->index = old->index;
	RCU_INIT_POINTER(twigs->parent, old->parent);

	qp_trie_update_parent(twigs, nr - 1);

	return twigs;
}

static struct bpf_qp_trie_key *qp_trie_init_leaf_node(struct bpf_map *map, void *k, void *v)
{
	struct bpf_qp_trie_key *key = k, *new;
	unsigned int key_size, total_size;

	key_size = sizeof(*key) + key->len;
	total_size = round_up(key_size + map->value_size, QP_TRIE_LEAF_ALLOC_ALIGN);
	new = bpf_map_kmalloc_node(map, total_size, GFP_NOWAIT | __GFP_NOWARN, map->numa_node);
	if (!new)
		return NULL;

	memcpy(new, k, key_size);
	memcpy((void *)new + key_size, v, map->value_size);

	return new;
}

static bool calc_prefix_len(const struct bpf_qp_trie_key *s_key,
			    const struct bpf_qp_trie_key *n_key, unsigned int *index)
{
	unsigned int len = min(s_key->len, n_key->len);
	unsigned int i;
	unsigned char diff = 0;

	for (i = 0; i < len; i++) {
		diff = s_key->data[i] ^ n_key->data[i];
		if (diff)
			break;
	}

	*index = (i << QP_TRIE_BYTE_INDEX_SHIFT) | QP_TRIE_NON_ROOT_NODE_MASK;
	if (!diff)
		return s_key->len == n_key->len;

	*index += (diff & 0xf0) ? 0 : (1U << QP_TRIE_NIBBLE_SHIFT);
	return false;
}

static int qp_trie_new_branch(struct qp_trie *trie, struct qp_trie_branch **parent,
			      unsigned int bitmap, void *sibling, struct qp_trie_diff *d,
			      void *key, void *value)
{
	struct qp_trie_branch *new_child_twigs, *new_twigs, *old_twigs;
	struct bpf_qp_trie_key *leaf;
	struct bpf_map *map;
	unsigned int iip;
	int err;

	map = &trie->map;
	if (atomic_inc_return(&trie->entries) > map->max_entries) {
		err = -ENOSPC;
		goto dec_entries;
	}

	leaf = qp_trie_init_leaf_node(map, key, value);
	if (!leaf) {
		err = -ENOMEM;
		goto dec_entries;
	}

	new_child_twigs = qp_trie_branch_new(map, 2);
	if (!new_child_twigs) {
		err = -ENOMEM;
		goto free_leaf;
	}

	new_child_twigs->index = d->index;
	new_child_twigs->bitmap = d->sibling_bm | d->new_bm;

	iip = calc_twig_index(new_child_twigs->bitmap, d->sibling_bm);
	RCU_INIT_POINTER(new_child_twigs->nodes[iip], sibling);
	rcu_assign_pointer(new_child_twigs->nodes[!iip], to_child_node(leaf));
	RCU_INIT_POINTER(new_child_twigs->parent, NULL);

	old_twigs = *parent;
	new_twigs = qp_trie_branch_replace(map, old_twigs, bitmap, new_child_twigs);
	if (!new_twigs) {
		err = -ENOMEM;
		goto free_child_twigs;
	}

	qp_trie_assign_parent(new_child_twigs, sibling);
	rcu_assign_pointer(*parent, new_twigs);
	qp_trie_branch_free(old_twigs, QP_TRIE_TWIGS_FREE_NONE_IDX);

	return 0;

free_child_twigs:
	kfree(new_child_twigs);
free_leaf:
	kfree(leaf);
dec_entries:
	atomic_dec(&trie->entries);
	return err;
}

static int qp_trie_ext_branch(struct qp_trie *trie, struct qp_trie_branch **parent,
			      void *key, void *value, unsigned int bitmap)
{
	struct qp_trie_branch *old_twigs, *new_twigs;
	struct bpf_qp_trie_key *new;
	struct bpf_map *map;
	int err;

	map = &trie->map;
	if (atomic_inc_return(&trie->entries) > map->max_entries) {
		err = -ENOSPC;
		goto dec_entries;
	}

	new = qp_trie_init_leaf_node(map, key, value);
	if (!new) {
		err = -ENOMEM;
		goto dec_entries;
	}

	old_twigs = *parent;
	new_twigs = qp_trie_branch_insert(map, old_twigs, bitmap, new);
	if (!new_twigs) {
		err = -ENOMEM;
		goto free_leaf;
	}

	rcu_assign_pointer(*parent, new_twigs);
	qp_trie_branch_free(old_twigs, QP_TRIE_TWIGS_FREE_NONE_IDX);

	return 0;

free_leaf:
	kfree(new);
dec_entries:
	atomic_dec(&trie->entries);
	return err;
}

static int qp_trie_add_leaf_node(struct qp_trie *trie, struct qp_trie_branch **parent,
				 void *key, void *value)
{
	struct bpf_map *map = &trie->map;
	struct qp_trie_branch *twigs;
	struct bpf_qp_trie_key *new;
	int err;

	if (atomic_inc_return(&trie->entries) > map->max_entries) {
		err = -ENOSPC;
		goto dec_entries;
	}

	new = qp_trie_init_leaf_node(map, key, value);
	if (!new) {
		err = -ENOMEM;
		goto dec_entries;
	}

	twigs = qp_trie_branch_new(map, 1);
	if (!twigs) {
		err = -ENOMEM;
		goto free_leaf;
	}
	twigs->index = QP_TRIE_ROOT_NODE_INDEX;
	twigs->bitmap = 1;
	RCU_INIT_POINTER(twigs->parent, NULL);
	rcu_assign_pointer(twigs->nodes[0], to_child_node(new));

	rcu_assign_pointer(*parent, twigs);

	return 0;
free_leaf:
	kfree(new);
dec_entries:
	atomic_dec(&trie->entries);
	return err;
}

static int qp_trie_rep_leaf_node(struct qp_trie *trie, struct qp_trie_branch **parent,
				 void *key, void *value, struct bpf_qp_trie_key *leaf,
				 unsigned int bitmap)
{
	struct qp_trie_branch *old_twigs, *new_twigs;
	struct bpf_map *map = &trie->map;
	struct bpf_qp_trie_key *new;
	int err;

	new = qp_trie_init_leaf_node(map, key, value);
	if (!new)
		return -ENOMEM;

	old_twigs = *parent;
	new_twigs = qp_trie_branch_replace(map, old_twigs, bitmap, to_child_node(new));
	if (!new_twigs) {
		err = -ENOMEM;
		goto free_leaf;
	}
	rcu_assign_pointer(*parent, new_twigs);

	qp_trie_branch_free(old_twigs, calc_twig_index(old_twigs->bitmap, bitmap));

	return 0;
free_leaf:
	kfree(new);
	return err;
}

static int qp_trie_remove_leaf(struct qp_trie *trie, struct qp_trie_branch **parent,
			       unsigned int bitmap, const struct bpf_qp_trie_key *node)
{
	struct bpf_map *map = &trie->map;
	struct qp_trie_branch *new, *old;
	unsigned int nr;

	old = *parent;
	nr = calc_twig_nr(old->bitmap);
	if (nr > 2) {
		new = qp_trie_branch_remove(map, old, bitmap);
		if (!new)
			return -ENOMEM;
	} else {
		new = NULL;
	}

	rcu_assign_pointer(*parent, new);

	qp_trie_branch_free(old, calc_twig_index(old->bitmap, bitmap));

	atomic_dec(&trie->entries);

	return 0;
}

static int qp_trie_merge_node(struct qp_trie *trie, struct qp_trie_branch **grand_parent,
			      struct qp_trie_branch *parent, unsigned int parent_bitmap,
			      unsigned int bitmap)
{
	struct qp_trie_branch *old_twigs, *new_twigs;
	struct bpf_map *map = &trie->map;
	void *new_sibling;
	unsigned int iip;

	iip = calc_twig_index(parent->bitmap, bitmap);
	new_sibling = parent->nodes[!iip];

	old_twigs = *grand_parent;
	new_twigs = qp_trie_branch_replace(map, old_twigs, parent_bitmap, new_sibling);
	if (!new_twigs)
		return -ENOMEM;

	rcu_assign_pointer(*grand_parent, new_twigs);

	qp_trie_branch_free(old_twigs, QP_TRIE_TWIGS_FREE_NONE_IDX);
	qp_trie_branch_free(parent, iip);

	atomic_dec(&trie->entries);

	return 0;
}

/* key and value are allocated together in qp_trie_init_leaf_node() */
static inline bool is_valid_k_v_size(unsigned int key_size, unsigned int value_size)
{
	return round_up((u64)key_size + value_size, QP_TRIE_LEAF_ALLOC_ALIGN) <=
	       KMALLOC_MAX_SIZE;
}

static int qp_trie_alloc_check(union bpf_attr *attr)
{
	if (!bpf_capable())
		return -EPERM;

	if (!(attr->map_flags | BPF_F_NO_PREALLOC) ||
	    attr->map_flags & ~QP_TRIE_CREATE_FLAG_MASK ||
	    !bpf_map_flags_access_ok(attr->map_flags))
		return -EINVAL;

	if (!attr->max_entries || attr->key_size < QP_TRIE_MIN_KEY_SIZE ||
	    !attr->value_size)
		return -EINVAL;

	if (attr->key_size > QP_TRIE_MAX_KEY_SIZE ||
	    !is_valid_k_v_size(attr->key_size, attr->value_size))
		return -E2BIG;

	return 0;
}

static struct bpf_map *qp_trie_alloc(union bpf_attr *attr)
{
	struct qp_trie *trie;
	unsigned int i;

	trie = bpf_map_area_alloc(sizeof(*trie), bpf_map_attr_numa_node(attr));
	if (!trie)
		return ERR_PTR(-ENOMEM);

	/* roots are zeroed by bpf_map_area_alloc() */
	for (i = 0; i < ARRAY_SIZE(trie->locks); i++)
		spin_lock_init(&trie->locks[i]);

	atomic_set(&trie->entries, 0);
	bpf_map_init_from_attr(&trie->map, attr);

	return &trie->map;
}

static void qp_trie_free_subtree(void *root)
{
	struct qp_trie_branch *parent = NULL;
	struct bpf_qp_trie_key *cur = NULL;
	void *node = root;

	/*
	 * Depth-first deletion
	 *
	 * 1. find left-most key and its parent
	 * 2. get next sibling Y from parent
	 * (a) Y is leaf node: continue
	 * (b) Y is branch node: goto step 1
	 * (c) no more sibling: backtrace upwards if parent is not NULL and
	 *     goto step 1
	 */
	do {
		while (is_branch_node(node)) {
			parent = node;
			node = rcu_dereference_protected(parent->nodes[0], 1);
		}

		cur = to_leaf_node(node);
		while (parent) {
			unsigned int iip, bitmap, nr;
			void *ancestor;

			bitmap = calc_br_bitmap(parent->index, cur);
			iip = calc_twig_index(parent->bitmap, bitmap) + 1;
			nr = calc_twig_nr(parent->bitmap);

			for (; iip < nr; iip++) {
				kfree(cur);

				node = rcu_dereference_protected(parent->nodes[iip], 1);
				if (is_branch_node(node))
					break;

				cur = to_leaf_node(node);
			}
			if (iip < nr)
				break;

			ancestor = rcu_dereference_protected(parent->parent, 1);
			kfree(parent);
			parent = ancestor;
		}
	} while (parent);

	kfree(cur);
}

static void qp_trie_free(struct bpf_map *map)
{
	struct qp_trie *trie = container_of(map, struct qp_trie, map);
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(trie->roots); i++) {
		void *root = rcu_dereference_protected(trie->roots[i], 1);

		if (root)
			qp_trie_free_subtree(root);
	}
	bpf_map_area_free(trie);
}

static inline void qp_trie_copy_leaf(struct bpf_qp_trie_key *leaf, void *key, unsigned int key_size)
{
	unsigned int used = sizeof(*leaf) + leaf->len;

	memcpy(key, leaf, used);
	memset(key + used, 0, key_size - used);
}

static void qp_trie_copy_min_key_from(void *root, void *next_key, unsigned int key_size)
{
	void *node;

	node = root;
	while (is_branch_node(node))
		node = rcu_dereference_raw(((struct qp_trie_branch *)node)->nodes[0]);

	qp_trie_copy_leaf(to_leaf_node(node), next_key, key_size);
}

static int qp_trie_lookup_min_key(struct qp_trie *trie, unsigned int from, void *next_key)
{
	unsigned int i;

	for (i = from; i < ARRAY_SIZE(trie->roots); i++) {
		void *root = rcu_dereference_raw(trie->roots[i]);

		if (root) {
			qp_trie_copy_min_key_from(root, next_key, trie->map.key_size);
			return 0;
		}
	}

	return -ENOENT;
}

static int qp_trie_next_twigs_index(struct qp_trie_branch *twigs, unsigned int bitmap)
{
	unsigned int idx, nr, next;

	/* bitmap may not in twigs->bitmap */
	idx = calc_twig_index(twigs->bitmap, bitmap);
	nr = calc_twig_nr(twigs->bitmap);

	next = idx;
	if (twigs->bitmap & bitmap)
		next += 1;

	if (next >= nr)
		return -1;
	return next;
}

static int qp_trie_lookup_next_node(struct qp_trie *trie, struct bpf_qp_trie_key *key,
				    void *next_key)
{
	struct qp_trie_branch *parent;
	struct bpf_qp_trie_key *found;
	void *node, *next;
	unsigned char c;

	if (!is_valid_key_data_len(key, trie->map.key_size))
		return -EINVAL;

	/* Non-exist key, so restart from the beginning */
	c = key->data[0];
	node = rcu_dereference_raw(trie->roots[c]);
	if (!node)
		return qp_trie_lookup_min_key(trie, 0, next_key);

	parent = NULL;
	while (is_branch_node(node)) {
		struct qp_trie_branch *br = node;
		unsigned int iip, bitmap;

		bitmap = calc_br_bitmap(br->index, key);
		if (bitmap & br->bitmap)
			iip = calc_twig_index(br->bitmap, bitmap);
		else
			iip = 0;

		parent = br;
		node = rcu_dereference_raw(br->nodes[iip]);
	}
	found = to_leaf_node(node);
	if (!is_same_key(found, key))
		return qp_trie_lookup_min_key(trie, 0, next_key);

	/* Pair with store release in rcu_assign_pointer(*parent, twigs) to
	 * ensure reading node->parent will not return the old parent if
	 * the node is found by following the newly-created parent.
	 */
	smp_rmb();

	next = NULL;
	while (parent) {
		unsigned int bitmap;
		int next_idx;

		bitmap = calc_br_bitmap(parent->index, key);
		next_idx = qp_trie_next_twigs_index(parent, bitmap);
		if (next_idx >= 0) {
			next = rcu_dereference_raw(parent->nodes[next_idx]);
			break;
		}
		parent = rcu_dereference_raw(parent->parent);
	}

	/* Goto next sub-tree */
	if (!next)
		return qp_trie_lookup_min_key(trie, c + 1, next_key);

	if (!is_branch_node(next))
		qp_trie_copy_leaf(to_leaf_node(next), next_key, trie->map.key_size);
	else
		qp_trie_copy_min_key_from(next, next_key, trie->map.key_size);

	return 0;
}

static int qp_trie_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	struct qp_trie *trie = container_of(map, struct qp_trie, map);
	struct bpf_qp_trie_key *cur_key = key;
	int err;

	if (!cur_key || !cur_key->len)
		err = qp_trie_lookup_min_key(trie, 0, next_key);
	else
		err = qp_trie_lookup_next_node(trie, cur_key, next_key);
	return err;
}

static void *qp_trie_lookup_elem(struct bpf_map *map, void *key)
{
	struct qp_trie *trie = container_of(map, struct qp_trie, map);
	struct bpf_qp_trie_key *trie_key = key, *found;
	unsigned char c = trie_key->data[0];
	void *node, *value;

	node = rcu_dereference_raw(trie->roots[c]);
	if (!node)
		return NULL;

	value = NULL;
	while (is_branch_node(node)) {
		struct qp_trie_branch *br = node;
		unsigned int bitmap;
		unsigned int iip;

		/* When byte index equals with key len, the target key
		 * may be in twigs->nodes[0].
		 */
		if (index_to_byte_index(br->index) > trie_key->len)
			goto done;

		bitmap = calc_br_bitmap(br->index, trie_key);
		if (!(bitmap & br->bitmap))
			goto done;

		iip = calc_twig_index(br->bitmap, bitmap);
		node = rcu_dereference_raw(br->nodes[iip]);
	}

	found = to_leaf_node(node);
	if (is_same_key(found, trie_key))
		value = qp_trie_leaf_value(found);
done:
	return value;
}

static int qp_trie_update_elem(struct bpf_map *map, void *key, void *value, u64 flags)
{
	struct qp_trie *trie = container_of(map, struct qp_trie, map);
	struct bpf_qp_trie_key *new_key = key, *leaf_key;
	struct qp_trie_branch **parent;
	struct qp_trie_diff d;
	unsigned int bitmap;
	spinlock_t *lock;
	void **node;
	unsigned char c;
	bool equal;
	int err;

	if (!is_valid_key_data_len(new_key, map->key_size) || flags > BPF_EXIST)
		return -EINVAL;

	c = new_key->data[0];
	lock = &trie->locks[c];
	spin_lock(lock);
	parent = (struct qp_trie_branch **)&trie->roots[c];
	if (!*parent) {
		if (flags == BPF_EXIST) {
			err = -ENOENT;
			goto unlock;
		}
		err = qp_trie_add_leaf_node(trie, parent, key, value);
		goto unlock;
	}

	bitmap = 1;
	node = &(*parent)->nodes[0];
	while (is_branch_node(*node)) {
		struct qp_trie_branch *br = *node;
		unsigned int iip;

		bitmap = calc_br_bitmap(br->index, new_key);
		if (bitmap & br->bitmap)
			iip = calc_twig_index(br->bitmap, bitmap);
		else
			iip = 0;
		parent = (struct qp_trie_branch **)node;
		node = &br->nodes[iip];
	}

	leaf_key = to_leaf_node(*node);
	equal = calc_prefix_len(leaf_key, new_key, &d.index);
	if (equal) {
		if (flags == BPF_NOEXIST) {
			err = -EEXIST;
			goto unlock;
		}
		err = qp_trie_rep_leaf_node(trie, parent, key, value, leaf_key, bitmap);
		goto unlock;
	}

	d.sibling_bm = calc_br_bitmap(d.index, leaf_key);
	d.new_bm = calc_br_bitmap(d.index, new_key);

	bitmap = 1;
	parent = (struct qp_trie_branch **)&trie->roots[c];
	node = &(*parent)->nodes[0];
	while (is_branch_node(*node)) {
		struct qp_trie_branch *br = *node;
		unsigned int iip;

		if (d.index < br->index)
			goto new_branch;

		parent = (struct qp_trie_branch **)node;
		if (d.index == br->index) {
			if (flags == BPF_EXIST) {
				err = -ENOENT;
				goto unlock;
			}
			err = qp_trie_ext_branch(trie, parent, key, value, d.new_bm);
			goto unlock;
		}

		bitmap = calc_br_bitmap(br->index, new_key);
		iip = calc_twig_index(br->bitmap, bitmap);
		node = &br->nodes[iip];
	}

new_branch:
	if (flags == BPF_EXIST) {
		err = -ENOENT;
		goto unlock;
	}
	err = qp_trie_new_branch(trie, parent, bitmap, *node, &d, key, value);
unlock:
	spin_unlock(lock);
	return err;
}

static int qp_trie_delete_elem(struct bpf_map *map, void *key)
{
	struct qp_trie *trie = container_of(map, struct qp_trie, map);
	struct qp_trie_branch **parent, **grand_parent;
	unsigned int bitmap = 1, parent_bitmap = 1, nr;
	struct bpf_qp_trie_key *trie_key = key, *found;
	spinlock_t *lock;
	void **node;
	unsigned char c;
	int err;

	if (!is_valid_key_data_len(trie_key, map->key_size))
		return -EINVAL;

	err = -ENOENT;
	grand_parent = NULL;
	c = trie_key->data[0];
	lock = &trie->locks[c];
	spin_lock(lock);
	parent = (struct qp_trie_branch **)&trie->roots[c];
	if (!*parent)
		goto unlock;

	node = &(*parent)->nodes[0];
	while (is_branch_node(*node)) {
		struct qp_trie_branch *br = *node;
		unsigned int iip;

		if (index_to_byte_index(br->index) > trie_key->len)
			goto unlock;

		parent_bitmap = bitmap;
		bitmap = calc_br_bitmap(br->index, trie_key);
		if (!(bitmap & br->bitmap))
			goto unlock;

		grand_parent = parent;
		parent = (struct qp_trie_branch **)node;
		iip = calc_twig_index(br->bitmap, bitmap);
		node = &br->nodes[iip];
	}

	found = to_leaf_node(*node);
	if (!is_same_key(found, trie_key))
		goto unlock;

	nr = calc_twig_nr((*parent)->bitmap);
	if (nr != 2)
		err = qp_trie_remove_leaf(trie, parent, bitmap, found);
	else
		err = qp_trie_merge_node(trie, grand_parent, *parent, parent_bitmap, bitmap);
unlock:
	spin_unlock(lock);
	return err;
}

static int qp_trie_check_btf(const struct bpf_map *map,
			     const struct btf *btf,
			     const struct btf_type *key_type,
			     const struct btf_type *value_type)
{
	/* TODO: key_type embeds bpf_qp_trie_key as its first member */
	return 0;
}

BTF_ID_LIST_SINGLE(qp_trie_map_btf_ids, struct, qp_trie)
const struct bpf_map_ops qp_trie_map_ops = {
	.map_alloc_check = qp_trie_alloc_check,
	.map_alloc = qp_trie_alloc,
	.map_free = qp_trie_free,
	.map_get_next_key = qp_trie_get_next_key,
	.map_lookup_elem = qp_trie_lookup_elem,
	.map_update_elem = qp_trie_update_elem,
	.map_delete_elem = qp_trie_delete_elem,
	.map_meta_equal = bpf_map_meta_equal,
	.map_check_btf = qp_trie_check_btf,
	.map_btf_id = &qp_trie_map_btf_ids[0],
};
