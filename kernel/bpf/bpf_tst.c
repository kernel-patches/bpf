// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2022. Huawei Technologies Co., Ltd */
#include <linux/bpf.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

/*
 * Ternary search tree is a special trie where nodes are arranged in
 * a manner similar to binary search tree, but with up to three children
 * rather than two. The three children correpond to nodes whose value is
 * less than, equal to, and greater than the value of current node
 * respectively.
 *
 * The following are illustrations of ternary search tree during inserting
 * hello, he, test, tea and team:
 *
 * 1. insert "hello"
 *
 *         [ hello ]
 *
 * 2. insert "he": need split "hello" into "he" and "llo"
 *
 *          [ he ]
 *             |
 *             *
 *             |
 *          [ llo ]
 *
 * 3. insert "test": add it as right child of "he"
 *
 *          [ he ]
 *             |
 *             *-------x
 *             |       |
 *          [ llo ] [ test ]
 *
 * 5. insert "tea": split "test" into "te" and "st",
 *    and insert "a" as left child of "st"
 *
 *          [ he ]
 *             |
 *      x------*-------x
 *      |      |       |
 *   [ ah ] [ llo ] [ te ]
 *                     |
 *                     *
 *                     |
 *                  [ st ]
 *                     |
 *                x----*
 *                |
 *              [ a ]
 *
 * 6. insert "team": insert "m" as middle child of "a"
 *
 *          [ he ]
 *             |
 *             *-------x
 *             |       |
 *          [ llo ] [ te ]
 *                     |
 *                     *
 *                     |
 *                  [ st ]
 *                     |
 *                x----*
 *                |
 *              [ a ]
 *                |
 *                *
 *                |
 *              [ m ]
 */
#define TST_CREATE_FLAG_MASK \
	(BPF_F_NUMA_NODE | BPF_F_NO_PREALLOC | BPF_F_ACCESS_MASK)

struct bpf_tst_node;

struct bpf_tst_node {
	struct rcu_head rcu;
	struct bpf_tst_node __rcu *child[3];
	u32 len;
	bool leaf;
	u8 key[];
};

struct bpf_tst {
	struct bpf_map map;
	struct bpf_tst_node __rcu *root;
	size_t nr_entries;
	spinlock_t lock;
};

/*
 * match_prefix() - check whether prefix is fully matched
 *
 * @next: returns the position of next-to-compare character in str
 *
 * Return 0 if str has prefix, 1 if str > prefix and -1 if str < prefix
 */
static int match_prefix(const unsigned char *prefix, int len,
			const unsigned char *str, int *next)
{
	int i;

	for (i = 0; i < len; i++) {
		int cmp = str[i] - prefix[i];

		if (cmp) {
			*next = i;
			return cmp > 0 ? 1 : -1;
		}
		if (!str[i])
			break;
	}

	*next = len;
	return 0;
}

/* Called from syscall or from eBPF program */
static void *tst_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_tst *tst = container_of(map, struct bpf_tst, map);
	struct bpf_tst_node *node;
	const unsigned char *c = key;

	/* A null terminated non-empty string */
	if (!c[0] || c[map->key_size - 1])
		return NULL;

	node = rcu_dereference_protected(tst->root, rcu_read_lock_held());
	while (node) {
		int cmp;
		int next;

		cmp = match_prefix(node->key, node->len, c, &next);
		/* Partially match an internal node */
		if (cmp && next)
			return NULL;

		c += next;
		/* Fully match */
		if (!cmp && !*c) {
			if (node->leaf)
				return node->key + node->len;
			return NULL;
		}

		node = rcu_dereference_protected(node->child[cmp + 1],
						 rcu_read_lock_held());
	}

	return NULL;
}

/* Split node into two nodes */
static struct bpf_tst_node *
split_tst_node(struct bpf_map *map, struct bpf_tst_node *node, int next, void *value)
{
	struct bpf_tst_node *bot, *top;
	size_t size;

	size = sizeof(*bot) + node->len - next;
	if (node->leaf)
		size += map->value_size;
	bot = bpf_map_kmalloc_node(map, size, GFP_ATOMIC | __GFP_NOWARN,
				   map->numa_node);
	if (!bot)
		return NULL;

	bot->child[0] = NULL;
	/* node has been initialized, so no rcu_assign_pointer() */
	bot->child[1] = node->child[1];
	bot->child[2] = NULL;
	bot->len = node->len - next;
	bot->leaf = node->leaf;
	memcpy(bot->key, node->key + next, bot->len);
	if (bot->leaf)
		memcpy(bot->key + bot->len, node->key + node->len,
		       map->value_size);

	size = sizeof(*top) + next;
	if (value)
		size += map->value_size;
	top = bpf_map_kmalloc_node(map, size, GFP_ATOMIC | __GFP_NOWARN,
				   map->numa_node);
	if (!top) {
		kfree(bot);
		return NULL;
	}

	top->child[0] = node->child[0];
	rcu_assign_pointer(top->child[1], bot);
	top->child[2] = node->child[2];
	top->len = next;
	top->leaf = !!value;
	memcpy(top->key, node->key, next);
	if (value)
		memcpy(top->key + top->len, value, map->value_size);

	return top;
}

static struct bpf_tst_node *
new_leaf_node(struct bpf_map *map, struct bpf_tst_node *node, bool replace,
	      const void *c, void *value)
{
	struct bpf_tst_node *leaf;
	size_t size;
	unsigned int str_len;

	/* Newly-created node or replace the original node */
	if (!replace)
		str_len = strlen(c);
	else
		str_len = node->len;
	size = sizeof(*leaf) + str_len + map->value_size;
	leaf = bpf_map_kmalloc_node(map, size, GFP_ATOMIC | __GFP_NOWARN,
				    map->numa_node);
	if (!leaf)
		return NULL;

	if (!replace) {
		leaf->child[0] = leaf->child[1] = leaf->child[2] = NULL;
		leaf->len = str_len;
		memcpy(leaf->key, c, str_len);
	} else {
		memcpy(leaf, node, sizeof(*node) + str_len);
	}
	leaf->leaf = true;
	memcpy(leaf->key + str_len, value, map->value_size);

	return leaf;
}

/* Called from syscall or from eBPF program */
static int tst_update_elem(struct bpf_map *map, void *key, void *value, u64 flags)
{
	struct bpf_tst *tst = container_of(map, struct bpf_tst, map);
	struct bpf_tst_node __rcu **slot, **new_slot = NULL;
	struct bpf_tst_node *node, *new_node, *new_intn_node = NULL;
	unsigned long irq_flags;
	const unsigned char *c = key;
	bool replace;
	int err = 0;

	if (!c[0] || c[map->key_size - 1])
		return -EINVAL;

	spin_lock_irqsave(&tst->lock, irq_flags);
	if (tst->nr_entries == map->max_entries) {
		err = -ENOSPC;
		goto out;
	}

	slot = &tst->root;
	while ((node = rcu_dereference_protected(*slot, lockdep_is_held(&tst->lock)))) {
		int cmp;
		int next;

		cmp = match_prefix(node->key, node->len, c, &next);
		c += next;

		/* Split internal node */
		if (cmp && next) {
			/* The split top node is a leaf node */
			bool top_leaf = !*c;

			new_node = split_tst_node(map, node, next,
						  top_leaf ? value : NULL);
			if (!new_node) {
				err = -ENOMEM;
				goto out;
			}
			if (top_leaf)
				goto done;

			new_intn_node = new_node;
			new_slot = &new_node->child[1]->child[cmp + 1];
			break;
		}

		/* Fully match */
		if (!cmp && !*c)
			break;
		slot = &node->child[cmp + 1];
	}

	/* Replace the original node ? */
	replace = node && !new_intn_node;
	new_node = new_leaf_node(map, node, replace, c, value);
	if (!new_node) {
		err = -ENOMEM;
		goto out;
	}

	/* Don't increase if replace a leaf node */
	if (!replace || !node->leaf)
		tst->nr_entries++;

	/* Graft the leaf node first for splitting */
	if (new_intn_node) {
		rcu_assign_pointer(*new_slot, new_node);
		new_node = new_intn_node;
	}
done:
	rcu_assign_pointer(*slot, new_node);
	spin_unlock_irqrestore(&tst->lock, irq_flags);
	kfree_rcu(node, rcu);

	return 0;
out:
	if (new_intn_node) {
		kfree(new_intn_node->child[1]);
		kfree(new_intn_node);
	}
	spin_unlock_irqrestore(&tst->lock, irq_flags);

	return err;
}

static int tst_delete_elem(struct bpf_map *map, void *key)
{
	return -EOPNOTSUPP;
}

static int tst_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	return -EOPNOTSUPP;
}

static struct bpf_map *tst_alloc(union bpf_attr *attr)
{
	struct bpf_tst *tst;

	if (!bpf_capable())
		return ERR_PTR(-EPERM);

	if (!attr->key_size || !attr->value_size ||
	    !attr->max_entries ||
	    !(attr->map_flags & BPF_F_NO_PREALLOC) ||
	    (attr->map_flags & ~TST_CREATE_FLAG_MASK) ||
	    !bpf_map_flags_access_ok(attr->map_flags))
		return ERR_PTR(-EINVAL);

	tst = kzalloc(sizeof(*tst), GFP_USER | __GFP_NOWARN | __GFP_ACCOUNT);
	if (!tst)
		return ERR_PTR(-ENOMEM);

	/* copy mandatory map attributes */
	bpf_map_init_from_attr(&tst->map, attr);
	spin_lock_init(&tst->lock);

	return &tst->map;
}

static void tst_free(struct bpf_map *map)
{
	struct bpf_tst *tst = container_of(map, struct bpf_tst, map);
	struct bpf_tst_node __rcu **slot;
	struct bpf_tst_node *node;

	/*
	 * Always start at the root and walk down to a node that has no
	 * children. Then free that node, nullify its reference in the parent
	 * and start over.
	 */
	for (;;) {
		slot = &tst->root;

		for (;;) {
			unsigned int i;

			node = rcu_dereference_protected(*slot, 1);
			if (!node)
				goto out;

			for (i = 0; i < ARRAY_SIZE(node->child); i++) {
				if (rcu_access_pointer(node->child[i])) {
					slot = &node->child[i];
					break;
				}
			}

			if (i < ARRAY_SIZE(node->child))
				continue;

			kfree(node);
			RCU_INIT_POINTER(*slot, NULL);
			break;
		}
	}

out:
	kfree(tst);
}

static int bpf_tst_map_btf_id;
const struct bpf_map_ops bpf_tst_map_ops = {
	.map_meta_equal = bpf_map_meta_equal,
	.map_alloc = tst_alloc,
	.map_free = tst_free,
	.map_get_next_key = tst_get_next_key,
	.map_lookup_elem = tst_lookup_elem,
	.map_update_elem = tst_update_elem,
	.map_delete_elem = tst_delete_elem,
	.map_btf_name = "bpf_tst",
	.map_btf_id = &bpf_tst_map_btf_id,
};
