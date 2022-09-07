// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 Isovalent, Inc.
 */

#include <linux/container_of.h>
#include <linux/btf_ids.h>
#include <linux/random.h>
#include <linux/jhash.h>
#include <linux/sort.h>
#include <linux/bpf.h>
#include <linux/err.h>
#include <linux/btf.h>
#include <linux/err.h>

#include <asm/unaligned.h>

typedef struct {
	u64 lo, hi;
} u128;

/* TYPE is one of u8, u16, u32 or u64 */
#define __mask(TYPE, PFX) \
	(PFX? (TYPE)-1 << ((sizeof(TYPE) * 8) - PFX) : 0)

#define __mask_prefix(TYPE, X, PFX) \
	(*(TYPE*)(X) & __mask(TYPE, (PFX)))

#define ____match_prefix(TYPE, RULE, PFX, ELEM) \
	(__mask_prefix(TYPE, (ELEM), PFX) == *(TYPE*)(RULE))

#define ____match_range(TYPE, X_MIN, X_MAX, X) \
	(*(TYPE*)(X_MIN) <= *(TYPE*)(X) && *(TYPE*)(X_MAX) >= *(TYPE*)(X))

static inline int
__match_prefix(u32 size, const void *prule, const void *pprefix, const void *pelem)
{
	u32 prefix = get_unaligned((u32 *)pprefix);

	if (size == 16) {
		u128 rule;
		u128 elem;

		rule.lo = get_unaligned((u64 *)prule);
		rule.hi = get_unaligned((u64 *)(prule+8));
		elem.lo = get_unaligned_be64((u64 *)pelem);
		elem.hi = get_unaligned_be64((u64 *)(pelem+8));

		if (prefix <= 64) {
			return ____match_prefix(u64, &rule.lo, prefix, &elem.lo);
		} else {
			return (rule.lo == elem.lo &&
				____match_prefix(u64, &rule.hi, prefix-64, &elem.hi));
		}
	} else if (size == 4) {
		u32 rule = get_unaligned((u32 *) prule);
		u32 elem = get_unaligned_be32(pelem);
		return ____match_prefix(u32, &rule, prefix, &elem);
	} else if (size == 8) {
		u64 rule = get_unaligned((u64 *) prule);
		u64 elem = get_unaligned_be64(pelem);
		return ____match_prefix(u64, &rule, prefix, &elem);
	} else if (size == 2) {
		u16 rule = get_unaligned((u16 *) prule);
		u16 elem = get_unaligned_be16(pelem);
		return ____match_prefix(u16, &rule, prefix, &elem);
	} else if (size == 1) {
		return ____match_prefix(u8, prule, prefix, pelem);
	}

	BUG();
	return 0;
}

static inline int
__match_range(u32 size, const void *pmin, const void *pmax, const void *pelem)
{
	if (size == 2) {
		u16 min = get_unaligned((u16 *) pmin);
		u16 max = get_unaligned((u16 *) pmax);
		u16 elem = get_unaligned_be16(pelem);
		return ____match_range(u16, &min, &max, &elem);
	} else if (size == 1) {
		return ____match_range(u8, pmin, pmax, pelem);
	} else if (size == 4) {
		u32 min = get_unaligned((u32 *) pmin);
		u32 max = get_unaligned((u32 *) pmax);
		u32 elem = get_unaligned_be32(pelem);
		return ____match_range(u32, &min, &max, &elem);
	} else if (size == 8) {
		u64 min = get_unaligned((u64 *) pmin);
		u64 max = get_unaligned((u64 *) pmax);
		u64 elem = get_unaligned_be64(pelem);
		return ____match_range(u64, &min, &max, &elem);
	}

	BUG();
	return 0;
}

static inline int __match_rule(const struct wildcard_rule_desc *desc,
			       const void *rule, const void *elem)
{
	u32 size = desc->size;

	switch (desc->type) {
	case BPF_WILDCARD_RULE_PREFIX:
		switch (size) {
		case 1: case 2: case 4: case 8: case 16:
			return __match_prefix(size, rule, rule+size, elem);
		}
		break;
	case BPF_WILDCARD_RULE_RANGE:
		switch (desc->size) {
		case 1: case 2: case 4: case 8:
			return __match_range(size, rule, rule+size, elem);
		}
		break;
	case BPF_WILDCARD_RULE_MATCH:
		return !memcmp(rule, elem, size);
	}

	BUG();
	return 0;
}

static inline int __match(const struct wildcard_desc *wc_desc,
			  const struct wildcard_key *rule,
			  const struct wildcard_key *elem)
{
	u32 off_rule = 0, off_elem = 0;
	u32 i, size;

	for (i = 0; i < wc_desc->n_rules; i++) {
		if (!__match_rule(&wc_desc->rule_desc[i],
				  &rule->data[off_rule],
				  &elem->data[off_elem]))
			return 0;

		size = wc_desc->rule_desc[i].size;
		switch (wc_desc->rule_desc[i].type) {
		case BPF_WILDCARD_RULE_PREFIX:
			off_rule += size + sizeof(u32);
			break;
		case BPF_WILDCARD_RULE_RANGE:
			off_rule += 2 * size;
			break;
		case BPF_WILDCARD_RULE_MATCH:
			off_rule += size;
			break;
		}
		off_elem += size;
	}
	return 1;
}

struct wildcard_ops;

union wildcard_lock {
	spinlock_t     lock;
	raw_spinlock_t raw_lock;
};

struct tm_bucket {
	struct hlist_head head;
};

struct tm_mask {
	u32 n_prefixes;
        u8 prefix[];
};

struct tm_table {
	struct list_head list;
	struct tm_mask *mask;
	atomic_t n_elements;
	struct rcu_head rcu;
	u32 id;
};

struct bpf_wildcard {
	struct bpf_map map;
	u32 elem_size;
	struct wildcard_ops *ops;
	struct wildcard_desc *desc;
	bool prealloc;
	bool priority;
	int algorithm;
	struct lock_class_key lockdep_key;

	/* currently, all map updates are protected by a single lock,
	 * so count is not atomic/percpu */
	int count;

	union {
		/* Brute Force */
		struct {
			struct hlist_head bf_elements_head;
			union wildcard_lock bf_lock;
		};

		/* TupleMerge */
		struct {
			struct tm_bucket *buckets;
			u32 n_buckets;

			union wildcard_lock tm_lock; /* one global lock to rule them all */

			struct list_head tables_list_head;

			bool static_tables_pool;
			struct list_head tables_pool_list_head;
		};
	};
};

struct wildcard_ops {
	int (*alloc)(struct bpf_wildcard *wcard,
		     const union bpf_attr *attr);
	void (*free)(struct bpf_wildcard *wcard);
	int (*get_next_key)(struct bpf_wildcard *wcard,
			    const struct wildcard_key *key,
			    struct wildcard_key *next_key);
	void *(*lookup)(const struct bpf_wildcard *wcard,
			const struct wildcard_key *key);
	void *(*match)(const struct bpf_wildcard *wcard,
		       const struct wildcard_key *key);
	int (*update_elem)(struct bpf_wildcard *wcard,
			   const struct wildcard_key *key,
			   void *value, u64 flags);
	int (*delete_elem)(struct bpf_wildcard *wcard,
			   const struct wildcard_key *key);
};

struct wcard_elem {

	struct bpf_wildcard *wcard;

	struct hlist_node node;
	struct rcu_head rcu;

	union {
		/* Brute Force */
		struct {
		};

		/* TupleMerge */
		struct {
			u32 table_id;
			u32 hash;
		};
	};

	char key[] __aligned(8);
};

static int check_map_update_flags(void *l_old, u64 map_flags)
{
	if (l_old && (map_flags & ~BPF_F_LOCK) == BPF_NOEXIST)
		/* elem already exists */
		return -EEXIST;

	if (!l_old && (map_flags & ~BPF_F_LOCK) == BPF_EXIST)
		/* elem doesn't exist, cannot update it */
		return -ENOENT;

	return 0;
}

static inline bool wcard_use_raw_lock(const struct bpf_wildcard *wcard)
{
	return (!IS_ENABLED(CONFIG_PREEMPT_RT) || wcard->prealloc);
}

static struct wcard_elem *
wcard_elem_alloc(struct bpf_wildcard *wcard, const void *key, void *value, void *l_old)
{
	struct bpf_map *map = &wcard->map;
	u32 key_size = map->key_size;
	struct wcard_elem *l;

	if (wcard->count >= wcard->map.max_entries && !l_old)
		return ERR_PTR(-E2BIG);

	wcard->count++;
	l = bpf_map_kmalloc_node(map, wcard->elem_size,
				 GFP_ATOMIC | __GFP_NOWARN, map->numa_node);
	if (unlikely(!l)) {
		wcard->count--;
		return ERR_PTR(-ENOMEM);
	}
	l->wcard = wcard;
	memcpy(l->key, key, key_size);
	copy_map_value(map, l->key + round_up(key_size, 8), value);
	return l;
}

static void __wcard_elem_free(struct wcard_elem *l)
{
	l->wcard->count--;
	kfree(l);
}

static void wcard_elem_free_rcu(struct rcu_head *head)
{
	struct wcard_elem *l = container_of(head, struct wcard_elem, rcu);

	__wcard_elem_free(l);
}

static void wcard_elem_free(struct wcard_elem *l)
{
	call_rcu(&l->rcu, wcard_elem_free_rcu);
}

static inline void wcard_init_lock(struct bpf_wildcard *wcard,
				   union wildcard_lock *lock)
{
	if (wcard_use_raw_lock(wcard)) {
		raw_spin_lock_init(&lock->raw_lock);
		lockdep_set_class(&lock->raw_lock, &wcard->lockdep_key);
	} else {
		spin_lock_init(&lock->lock);
		lockdep_set_class(&lock->lock, &wcard->lockdep_key);
	}
}

static inline int wcard_lock(struct bpf_wildcard *wcard,
			     union wildcard_lock *lock,
			     unsigned long *pflags)
{
	unsigned long flags;

	if (wcard_use_raw_lock(wcard))
		raw_spin_lock_irqsave(&lock->raw_lock, flags);
	else
		spin_lock_irqsave(&lock->lock, flags);
	*pflags = flags;

	return 0;
}

static inline void wcard_unlock(struct bpf_wildcard *wcard,
				union wildcard_lock *lock,
				unsigned long flags)
{
	if (wcard_use_raw_lock(wcard))
		raw_spin_unlock_irqrestore(&lock->raw_lock, flags);
	else
		spin_unlock_irqrestore(&lock->lock, flags);
}

static inline int bf_lock(struct bpf_wildcard *wcard, unsigned long *pflags)
{
	return wcard_lock(wcard, &wcard->bf_lock, pflags);
}

static inline void bf_unlock(struct bpf_wildcard *wcard, unsigned long flags)
{
	return wcard_unlock(wcard, &wcard->bf_lock, flags);
}

static void *bf_match(const struct bpf_wildcard *wcard,
		      const struct wildcard_key *key)
{
	struct wcard_elem *l;

	hlist_for_each_entry_rcu(l, &wcard->bf_elements_head, node)
		if (__match(wcard->desc, (struct wildcard_key *)l->key, key))
			return l;

	return NULL;
}

static void *bf_lookup(const struct bpf_wildcard *wcard,
		       const struct wildcard_key *key)
{
	struct wcard_elem *l;

	hlist_for_each_entry_rcu(l, &wcard->bf_elements_head, node)
		if (!memcmp(l->key, key, wcard->map.key_size))
			return l;

	return NULL;
}

static int bf_update_elem(struct bpf_wildcard *wcard,
			  const struct wildcard_key *key,
			  void *value, u64 map_flags)
{
	struct wcard_elem *l_old, *l_new;
	unsigned long irq_flags;
	int ret;

	ret = bf_lock(wcard, &irq_flags);
	if (ret)
		return ret;

	l_old = bf_lookup(wcard, key);
	ret = check_map_update_flags(l_old, map_flags);
	if (ret)
		goto unlock;

	l_new = wcard_elem_alloc(wcard, key, value, l_old);
	if (IS_ERR(l_new)) {
		ret = PTR_ERR(l_new);
		goto unlock;
	}

	if (l_old) {
		hlist_replace_rcu(&l_old->node, &l_new->node);
		wcard_elem_free(l_old);
	} else {
		hlist_add_head_rcu(&l_new->node, &wcard->bf_elements_head);
	}

unlock:
	bf_unlock(wcard, irq_flags);
	return ret;
}

static int bf_get_next_key(struct bpf_wildcard *wcard,
			   const struct wildcard_key *key,
			   struct wildcard_key *next_key)
{
	struct wcard_elem *l = NULL;
	struct hlist_node *node;

	if (key)
		l = bf_lookup(wcard, key);

	if (!l)
		/* invalid key, get the first element */
		node = rcu_dereference_raw(hlist_first_rcu(&wcard->bf_elements_head));
	else
		/* valid key, get the next element */
		node = rcu_dereference_raw(hlist_next_rcu(&l->node));

	l = hlist_entry_safe(node, struct wcard_elem, node);
	if (!l)
		return -ENOENT;

	memcpy(next_key, l->key, wcard->map.key_size);
	return 0;
}

static int bf_delete_elem(struct bpf_wildcard *wcard,
			  const struct wildcard_key *key)
{
	struct wcard_elem *elem;
	unsigned long irq_flags;
	int err;

	err = bf_lock(wcard, &irq_flags);
	if (err)
		return err;

	elem = bf_lookup(wcard, key);
	if (elem) {
		hlist_del_rcu(&elem->node);
		wcard_elem_free(elem);
	} else {
		err = -ENOENT;
	}

	bf_unlock(wcard, irq_flags);
	return err;
}

static int bf_alloc(struct bpf_wildcard *wcard, const union bpf_attr *attr)
{
	INIT_HLIST_HEAD(&wcard->bf_elements_head);
	wcard_init_lock(wcard, &wcard->bf_lock);
	return 0;
}

static void bf_free(struct bpf_wildcard *wcard)
{
	struct hlist_node *n;
	struct wcard_elem *l;

	hlist_for_each_entry_safe(l, n, &wcard->bf_elements_head, node) {
		hlist_del(&l->node);
		__wcard_elem_free(l);
	}
}

static void __tm_copy_masked_rule(void *dst, const void *data, u32 size, u32 prefix)
{
	if (size == 1) {
		u8 x = *(u8 *)data;
		x = __mask_prefix(u8, &x, prefix);
		memcpy(dst, &x, 1);
	} else if (size == 2) {
		u16 x = get_unaligned((u16 *) data);
		x = __mask_prefix(u16, &x, prefix);
		memcpy(dst, &x, 2);
	} else if (size == 4) {
		u32 x = get_unaligned((u32 *) data);
		x = __mask_prefix(u32, &x, prefix);
		memcpy(dst, &x, 4);
	} else if (size == 8) {
		u64 x = get_unaligned((u64 *) data);
		x = __mask_prefix(u64, &x, prefix);
		memcpy(dst, &x, 8);
	} else if (size == 16) {
		u128 x;

		x.lo = get_unaligned((u64 *)data);
		x.hi = get_unaligned((u64 *)(data+8));

		/* if prefix is less than 64, then we will zero out the lower
		 * part in any case, otherwise we won't mask out any bits from
		 * the higher part; in any case, first we copy the lower part */
		if (prefix <= 64) {
			x.hi = 0;
			x.lo = __mask_prefix(u64, &x.lo, prefix);
		} else {
			x.hi = __mask_prefix(u64, &x.hi, prefix-64);
		}
		memcpy(dst, &x, 16);
	}
}

static void __tm_copy_masked_elem(void *dst, const void *data, u32 size, u32 prefix)
{
	if (size == 1) {
		u8 x = *(u8 *)data;
		x = __mask_prefix(u8, &x, prefix);
		memcpy(dst, &x, 1);
	} else if (size == 2) {
		u16 x = get_unaligned_be16(data);
		x = __mask_prefix(u16, &x, prefix);
		memcpy(dst, &x, 2);
	} else if (size == 4) {
		u32 x = get_unaligned_be32(data);
		x = __mask_prefix(u32, &x, prefix);
		memcpy(dst, &x, 4);
	} else if (size == 8) {
		u64 x = get_unaligned_be64(data);
		x = __mask_prefix(u64, &x, prefix);
		memcpy(dst, &x, 8);
	} else if (size == 16) {
		u128 x;

		x.lo = get_unaligned_be64(data);
		x.hi = get_unaligned_be64(data+8);

		/* if prefix is less than 64, then we will zero out the lower
		 * part in any case, otherwise we won't mask out any bits from
		 * the higher part; in any case, first we copy the lower part */
		if (prefix <= 64) {
			x.lo = __mask_prefix(u64, &x.lo, prefix);
			x.hi = 0;
		} else {
			x.hi = __mask_prefix(u64, &x.hi, prefix-64);
		}
		memcpy(dst, &x, 16);
	}
}

static u32 tm_hash_rule(const struct wildcard_desc *desc,
			const struct tm_table *table,
			const struct wildcard_key *key)
{
	u8 buf[BPF_WILDCARD_MAX_TOTAL_RULE_SIZE];
	const void *data = key->data;
	u32 type, size, i;
	u32 n = 0;

	for (i = 0; i < desc->n_rules; i++) {

		type = desc->rule_desc[i].type;
		size = desc->rule_desc[i].size;

		if (type == BPF_WILDCARD_RULE_RANGE ||
		    (type == BPF_WILDCARD_RULE_PREFIX && !table->mask->prefix[i]))
			goto ignore;

		if (likely(type == BPF_WILDCARD_RULE_PREFIX))
			__tm_copy_masked_rule(buf+n, data, size, table->mask->prefix[i]);
		else if (type == BPF_WILDCARD_RULE_MATCH)
			memcpy(buf+n, data, size);

		n += size;
ignore:
		switch (desc->rule_desc[i].type) {
		case BPF_WILDCARD_RULE_PREFIX:
			data += size + sizeof(u32);
			break;
		case BPF_WILDCARD_RULE_RANGE:
			data += 2 * size;
			break;
		case BPF_WILDCARD_RULE_MATCH:
			data += size;
			break;
		}
	}

	return jhash(buf, n, table->id);
}

static u32 tm_hash(const struct wildcard_desc *desc,
		   const struct tm_table *table,
		   const struct wildcard_key *key)
{
	u8 buf[BPF_WILDCARD_MAX_TOTAL_RULE_SIZE];
	const void *data = key->data;
	u32 type, size, i;
	u32 n = 0;

	for (i = 0; i < desc->n_rules; i++) {

		type = desc->rule_desc[i].type;
		size = desc->rule_desc[i].size;

		if (type == BPF_WILDCARD_RULE_RANGE ||
		    (type == BPF_WILDCARD_RULE_PREFIX && !table->mask->prefix[i]))
			goto ignore;

		if (likely(type == BPF_WILDCARD_RULE_PREFIX))
			__tm_copy_masked_elem(buf+n, data, size, table->mask->prefix[i]);
		else if (type == BPF_WILDCARD_RULE_MATCH)
			memcpy(buf+n, data, size);

		n += size;
ignore:
		data += size;
	}

	return jhash(buf, n, table->id);
}

static struct wcard_elem *__tm_lookup(const struct bpf_wildcard *wcard,
				      const struct wildcard_key *key,
				      struct tm_table **table_ptr,
				      struct tm_bucket **bucket_ptr)
{
	struct tm_bucket *bucket;
	struct tm_table *table;
	struct wcard_elem *l;
	u32 hash;

	list_for_each_entry_rcu(table, &wcard->tables_list_head, list) {
		hash = tm_hash_rule(wcard->desc, table, key);
		bucket = &wcard->buckets[hash & (wcard->n_buckets - 1)];
		hlist_for_each_entry_rcu(l, &bucket->head, node) {
			if (l->hash != hash)
				continue;
			if (l->table_id != table->id)
				continue;
			if (!memcmp(l->key, key, wcard->map.key_size)) {
				if (table_ptr)
					*table_ptr = table;
				if (bucket_ptr)
					*bucket_ptr = bucket;
				return l;
			}
		}
	}
	return NULL;
}

static void *tm_match(const struct bpf_wildcard *wcard,
		      const struct wildcard_key *key)
{
	struct tm_bucket *bucket;
	struct tm_table *table;
	struct wcard_elem *l;
	u32 hash;

	list_for_each_entry_rcu(table, &wcard->tables_list_head, list) {
		hash = tm_hash(wcard->desc, table, key);
		bucket = &wcard->buckets[hash & (wcard->n_buckets - 1)];
		hlist_for_each_entry_rcu(l, &bucket->head, node) {
			if (l->hash != hash)
				continue;
			if (l->table_id != table->id)
				continue;
			if (__match(wcard->desc, (void *)l->key, key))
				return l;
		}
	}
	return NULL;
}
static void *tm_lookup(const struct bpf_wildcard *wcard,
		       const struct wildcard_key *key)
{
	return __tm_lookup(wcard, key, NULL, NULL);
}

static void __tm_table_free(struct tm_table *table)
{
	bpf_map_area_free(table);
}

static void tm_table_free_rcu(struct rcu_head *head)
{
	struct tm_table *table = container_of(head, struct tm_table, rcu);

	__tm_table_free(table);
}

static void tm_table_free(struct tm_table *table)
{
	call_rcu(&table->rcu, tm_table_free_rcu);
}

static bool __tm_table_id_exists(struct list_head *head, u32 id)
{
	struct tm_table *table;

	list_for_each_entry(table, head, list)
		if (table->id == id)
			return true;

	return false;
}

static u32 tm_new_table_id(struct bpf_wildcard *wcard, bool dynamic)
{
	struct list_head *head;
	u32 id;

	if (dynamic)
		head = &wcard->tables_list_head;
	else
		head = &wcard->tables_pool_list_head;

	do
		id = get_random_u32();
	while (__tm_table_id_exists(head, id));

	return id;
}

static struct tm_table *tm_new_table(struct bpf_wildcard *wcard,
				     const struct wildcard_key *key,
				     bool circumcision, bool dynamic)
{
	struct tm_table *table;
	u32 off = 0;
	u32 size, i;
	u32 prefix;

	/*
	 * struct tm_table | struct tm_mask | u8 prefixes[n_rules]
	 *        \             ^       \           ^
	 *         -------------|        -----------|
	 */
	size = sizeof(*table) + sizeof(struct tm_mask) + wcard->desc->n_rules;

	table = bpf_map_kmalloc_node(&wcard->map, size,
				     GFP_ATOMIC | __GFP_NOWARN,
				     wcard->map.numa_node);
	if (!table)
		return NULL;

	table->id = tm_new_table_id(wcard, dynamic);
	table->mask = (struct tm_mask *)(table + 1);
	atomic_set(&table->n_elements, 0);

	table->mask->n_prefixes = wcard->desc->n_rules;
	for (i = 0; i < wcard->desc->n_rules; i++) {
		size = wcard->desc->rule_desc[i].size;

		switch (wcard->desc->rule_desc[i].type) {
		case BPF_WILDCARD_RULE_PREFIX:
			prefix = *(u32 *)(key->data + off + size);
			table->mask->prefix[i] = prefix;
			if (circumcision)
				table->mask->prefix[i] -= prefix/8;
			off += size + sizeof(u32);
			break;
		case BPF_WILDCARD_RULE_RANGE:
			table->mask->prefix[i] = 0;
			off += 2 * size;
			break;
		case BPF_WILDCARD_RULE_MATCH:
			table->mask->prefix[i] = 0;
			off += size;
			break;
		default:
			BUG();
		}
	}

	return table;
}

static struct tm_table *tm_new_table_from_mask(struct bpf_wildcard *wcard,
					       const u8 *prefixes,
					       u32 n_prefixes, bool dynamic)
{
	struct tm_table *table;
	u32 size;

	BUG_ON(wcard->desc->n_rules != n_prefixes);

	/*
	 * struct tm_table | struct tm_mask | u8 prefixes[n_rules]
	 *        \             ^       \           ^
	 *         -------------|        -----------|
	 */
	size = sizeof(*table) + sizeof(struct tm_mask) + wcard->desc->n_rules;

	table = bpf_map_kmalloc_node(&wcard->map, size,
				     GFP_ATOMIC | __GFP_NOWARN,
				     wcard->map.numa_node);
	if (!table)
		return NULL;

	table->id = tm_new_table_id(wcard, dynamic);
	table->mask = (struct tm_mask *)(table + 1);
	atomic_set(&table->n_elements, 0);

	table->mask->n_prefixes = wcard->desc->n_rules;
	memcpy(table->mask->prefix, prefixes, table->mask->n_prefixes);

	return table;
}

static int tm_table_compatible(const struct bpf_wildcard *wcard,
			       const struct tm_table *table,
			       const struct wildcard_key *key)
{
	u32 off = 0;
	u32 size, i;
	u32 prefix;

	for (i = 0; i < wcard->desc->n_rules; i++) {
		size = wcard->desc->rule_desc[i].size;

		switch (wcard->desc->rule_desc[i].type) {
		case BPF_WILDCARD_RULE_PREFIX:
			prefix = *(u32 *)(key->data + off + size);

			/* table only is compatible if its prefix is less than or equal rule prefix */
			if (table->mask->prefix[i] > prefix)
				return 0;

			off += size + sizeof(u32);
			break;
		case BPF_WILDCARD_RULE_RANGE:
			/* ignore this case, table is always compatible */
			off += 2 * size;
			break;
		case BPF_WILDCARD_RULE_MATCH:
			/* ignore this case, table is always compatible */
			off += size;
			break;
		}
	}
	return 1;
}

static void tm_add_new_table(struct bpf_wildcard *wcard, struct tm_table *table)
{
	list_add_tail_rcu(&table->list, &wcard->tables_list_head);
}

static struct tm_table *tm_get_dynamic_table(struct bpf_wildcard *wcard,
					     const struct wildcard_key *key)
{
	struct tm_table *table;

	list_for_each_entry(table, &wcard->tables_list_head, list)
		if (tm_table_compatible(wcard, table, key))
			return table;

	table = tm_new_table(wcard, key, true, true);
	if (!table)
		return ERR_PTR(-ENOMEM);

	tm_add_new_table(wcard, table);
	return table;
}

static bool tm_same_table(struct tm_table *a, struct tm_table *b)
{
	BUG_ON(a->mask->n_prefixes != b->mask->n_prefixes);
	return !memcmp(a->mask->prefix, b->mask->prefix, a->mask->n_prefixes);
}

static struct tm_table *tm_get_static_table(struct bpf_wildcard *wcard,
					    const struct wildcard_key *key)
{
	struct tm_table *static_table, *table;
	bool found = false;

	/* Find a static table which is compatible with the key. This is
	 * possible that the key doesn't fit into any static tables */
	list_for_each_entry(static_table, &wcard->tables_pool_list_head, list)
		if (tm_table_compatible(wcard, static_table, key)) {
			found = true;
			break;
		}
	if (!found)
		return ERR_PTR(-EINVAL);

	/* Check if this static_table is listed alerady in the active list */
	list_for_each_entry(table, &wcard->tables_list_head, list)
		if (tm_same_table(table, static_table))
			return table;

	table = tm_new_table_from_mask(wcard, static_table->mask->prefix,
				       static_table->mask->n_prefixes, true);
	if (!table)
		return ERR_PTR(-ENOMEM);

	tm_add_new_table(wcard, table);
	return table;
}

static struct tm_table *tm_compatible_table(struct bpf_wildcard *wcard,
					    const struct wildcard_key *key)
{
	if (wcard->static_tables_pool) {
		return tm_get_static_table(wcard, key);
	} else {
		return tm_get_dynamic_table(wcard, key);
	}
}

static inline int tm_lock(struct bpf_wildcard *wcard, unsigned long *pflags)
{
	return wcard_lock(wcard, &wcard->tm_lock, pflags);
}

static inline void tm_unlock(struct bpf_wildcard *wcard, unsigned long flags)
{
	return wcard_unlock(wcard, &wcard->tm_lock, flags);
}

static int __tm_update_elem(struct bpf_wildcard *wcard,
			    const struct wildcard_key *key,
			    void *value, u64 map_flags)
{
	struct bpf_map *map = &wcard->map;
	struct tm_bucket *bucket;
	struct tm_table *table;
	struct wcard_elem *l;
	u32 hash;
	int ret;

	l = tm_lookup(wcard, key);
	ret = check_map_update_flags(l, map_flags);
	if (ret)
		return ret;
	if (l) {
		copy_map_value(map, l->key + round_up(map->key_size, 8), value);
		return 0;
	}

	l = wcard_elem_alloc(wcard, key, value, NULL);
	if (IS_ERR(l))
		return PTR_ERR(l);

	table = tm_compatible_table(wcard, key);
	if (IS_ERR(table)) {
		__wcard_elem_free(l);
		return PTR_ERR(table);
	}

	hash = tm_hash_rule(wcard->desc, table, (void*)l->key);
	bucket = &wcard->buckets[hash & (wcard->n_buckets - 1)];
	l->hash = hash;
	l->table_id = table->id;
	atomic_inc(&table->n_elements);

	hlist_add_head_rcu(&l->node, &bucket->head);
	return 0;
}

static int __tm_delete_elem(struct bpf_wildcard *wcard,
			    const struct wildcard_key *key)
{
	struct tm_bucket *bucket;
	struct wcard_elem *elem;
	struct tm_table *table;
	int n;

	elem = __tm_lookup(wcard, key, &table, &bucket);
	if (!elem)
		return -ENOENT;

	hlist_del_rcu(&elem->node);
	wcard_elem_free(elem);

	n = atomic_dec_return(&table->n_elements);
	if (n == 0) {
		list_del_rcu(&table->list);
		tm_table_free(table);
	}

	return 0;
}

static int __tm_cmp_u8_descending(const void *a, const void *b)
{
	return (int)*(u8*)b - (int)*(u8*)a;
}

#define lengths(I)	wcard->desc->rule_desc[I].n_prefixes
#define prefix(I, J)	((u8)(lengths(I) ? wcard->desc->rule_desc[I].prefixes[J] : 0))
#define masks(I, J)	(*(u8*)(mask + (J) * m + I))

static void *__tm_alloc_pool_cartesian(struct bpf_wildcard *wcard, u32 *np)
{
	u32 n, m = wcard->desc->n_rules;
	void *mask;
	int *idx;
	u32 i, j;

	/*
	 * Each element in rule has an array prefixes[n_prefixes], and we need
	 * to build a Cartesian product of theese arrays. Say, we have ([16,8],
	 * [24,16], [], []). Then we construct the following Cartesian product:
	 *   (16, 24, 0, 0)
	 *   (8, 24, 0, 0)
	 *   (16, 16, 0, 0)
	 *   (8, 16, 0, 0)
	 */

	n = 1;
	for (i = 0; i < m; i++) {
		if (!lengths(i))
			continue;
		if (wcard->desc->rule_desc[i].type != BPF_WILDCARD_RULE_PREFIX)
			return ERR_PTR(-EINVAL);

		/* Prefixes should be sorted in descending order, otherwise
		 * lower tables won't be ever reached */
		sort(wcard->desc->rule_desc[i].prefixes, lengths(i),
		     sizeof(wcard->desc->rule_desc[i].prefixes[0]),
		     __tm_cmp_u8_descending, NULL);

		n *= lengths(i);
	}

	mask = kzalloc(n * m + m * sizeof(*idx), GFP_USER);
	if (!mask)
		return ERR_PTR(-ENOMEM);

	idx = mask + n * m;
	for (j = 0; j < n; j++) {
		for (i = 0; i < m; i++)
			masks(i, j) = prefix(i, idx[i]);

		i = 0;
		idx[i]++;
		while (idx[i] == lengths(i)) {
			idx[i++] = 0;
			if (lengths(i))
				idx[i]++;
		}
	}

	*np = n;
	return mask;
}

static void *__tm_alloc_pool_list(struct bpf_wildcard *wcard, u32 *np)
{
	u32 n, m = wcard->desc->n_rules;
	void *mask;
	u32 i, j;

	/*
	 * Each element in rule has an array prefixes[n_prefixes], and we need
	 * to build a combined list of theese arrays. Say, we have ([16,8],
	 * [16,8], [], []). Then we construct the following list:
	 *   (16, 16, 0, 0)
	 *   (8, 8, 0, 0)
	 */

	n = 0;
	for (i = 0; i < m; i++) {
		if (!lengths(i))
			continue;
		if (wcard->desc->rule_desc[i].type != BPF_WILDCARD_RULE_PREFIX)
			return ERR_PTR(-EINVAL);

		/* We do not sort elements for lists because users might want
		 * to specify pools like (32,32),(32,0),(0,32). If sorted,
		 * then this will be interpreted as (32,32),(32,32),(0,0) */

		/* All the lists should be of the same length, or empty */
		if (n == 0)
			n = lengths(i);
		else if (n != lengths(i))
			return ERR_PTR(-EINVAL);
	}

	mask = kzalloc(n * m, GFP_USER);
	if (!mask)
		return ERR_PTR(-ENOMEM);

	for (i = 0; i < m; i++)
		for (j = 0; j < n; j++)
			masks(i, j) = prefix(i, j);

	*np = n;
	return mask;
}

#undef lengths
#undef prefix
#undef masks

static int tm_alloc_static_tables_pool(struct bpf_wildcard *wcard,
				       bool cartesian)
{
	u32 n, m = wcard->desc->n_rules;
	struct tm_table *table;
	int err = 0;
	void *mask;
	u32 j;

	if (cartesian)
		mask = __tm_alloc_pool_cartesian(wcard, &n);
	else
		mask = __tm_alloc_pool_list(wcard, &n);
	if (IS_ERR(mask))
		return PTR_ERR(mask);

	for (j = 0; j < n; j++) {
		table = tm_new_table_from_mask(wcard, mask + j * m, m, false);
		if (!table) {
			err = -ENOMEM;
			goto free_mem;
		}
		list_add_tail(&table->list, &wcard->tables_pool_list_head);
	}

free_mem:
	kfree(mask);
	return err;
}

static int tm_update_elem(struct bpf_wildcard *wcard,
			  const struct wildcard_key *key,
			  void *value, u64 flags)
{
	unsigned long irq_flags;
	int ret;

	ret = tm_lock(wcard, &irq_flags);
	if (ret)
		return ret;
	ret = __tm_update_elem(wcard, key, value, flags);
	tm_unlock(wcard, irq_flags);
	return ret;
}

static int tm_delete_elem(struct bpf_wildcard *wcard,
			  const struct wildcard_key *key)
{
	unsigned long irq_flags;
	int ret;

	ret = tm_lock(wcard, &irq_flags);
	if (ret)
		return ret;
	ret = __tm_delete_elem(wcard, key);
	tm_unlock(wcard, irq_flags);
	return ret;
}

static int tm_get_next_key(struct bpf_wildcard *wcard,
			   const struct wildcard_key *key,
			   struct wildcard_key *next_key)
{
	struct tm_bucket *bucket;
	struct hlist_node *node;
	struct wcard_elem *l;
	unsigned int i = 0;

	if (!key)
		goto find_first_elem;

	l = __tm_lookup(wcard, key, NULL, &bucket);
	if (!l)
		goto find_first_elem;

	node = rcu_dereference_raw(hlist_next_rcu(&l->node));
	l = hlist_entry_safe(node, struct wcard_elem, node);
	if (l)
		goto copy;

	i = (bucket - wcard->buckets) + 1;

find_first_elem:
	for (; i < wcard->n_buckets; i++) {
		bucket = &wcard->buckets[i];
		node = rcu_dereference_raw(hlist_first_rcu(&bucket->head));
		l = hlist_entry_safe(node, struct wcard_elem, node);
		if (l)
			goto copy;
	}
	return -ENOENT;

copy:
	memcpy(next_key, l->key, wcard->map.key_size);
	return 0;
}

static void tm_free_bucket(struct tm_bucket *bucket)
{
	struct hlist_node *n;
	struct wcard_elem *l;

	hlist_for_each_entry_safe(l, n, &bucket->head, node) {
		hlist_del(&l->node);
		__wcard_elem_free(l);
	}
}

static void tm_free(struct bpf_wildcard *wcard)
{
	struct tm_table *table, *n;
	unsigned int i;

	if (wcard->buckets) {
		for (i = 0; i < wcard->n_buckets; i++)
			tm_free_bucket(&wcard->buckets[i]);
		bpf_map_area_free(wcard->buckets);
	}

	list_for_each_entry_safe(table, n, &wcard->tables_list_head, list)
		__tm_table_free(table);

	if (wcard->static_tables_pool)
		list_for_each_entry_safe(table, n, &wcard->tables_pool_list_head, list)
			__tm_table_free(table);
}

static int tm_alloc(struct bpf_wildcard *wcard, const union bpf_attr *attr)
{
	unsigned int i;
	int err;

	wcard->n_buckets = roundup_pow_of_two(wcard->map.max_entries);
	wcard->buckets = bpf_map_area_alloc(wcard->n_buckets *
					   sizeof(struct tm_bucket),
					   wcard->map.numa_node);
	if (!wcard->buckets)
		return -ENOMEM;

	for (i = 0; i < wcard->n_buckets; i++)
		INIT_HLIST_HEAD(&wcard->buckets[i].head);

	INIT_LIST_HEAD(&wcard->tables_list_head);
	wcard_init_lock(wcard, &wcard->tm_lock);

	/* this flag means that we need to pre-allocate a list of tables to
	 * pull tables from; it should be provided by user. Otherwise we don't
	 * know what to do. However, we can try to do two things: either
	 * pre-allocate tables based on the field size / rule type (only
	 * /prefix rules require a non-zero prefix), or to do a dynamic
	 * allocation as in classic TM
	 */
	wcard->static_tables_pool = !!(attr->map_extra & BPF_WILDCARD_F_TM_STATIC_POOL);

	if (wcard->static_tables_pool) {
		INIT_LIST_HEAD(&wcard->tables_pool_list_head);
		err = tm_alloc_static_tables_pool(wcard,
						  !(attr->map_extra &
						    BPF_WILDCARD_F_TM_POOL_LIST));
		if (err)
			goto free_buckets;
	}

	return 0;

free_buckets:
	bpf_map_area_free(wcard->buckets);
	return err;
}

static struct wildcard_ops wildcard_algorithms[BPF_WILDCARD_F_ALGORITHM_MAX] = {
	[BPF_WILDCARD_F_ALGORITHM_BF] = {
		.alloc = bf_alloc,
		.free = bf_free,
		.get_next_key = bf_get_next_key,
		.lookup = bf_lookup,
		.match = bf_match,
		.update_elem = bf_update_elem,
		.delete_elem = bf_delete_elem,
	},
	[BPF_WILDCARD_F_ALGORITHM_TM] = {
		.alloc = tm_alloc,
		.free = tm_free,
		.get_next_key = tm_get_next_key,
		.lookup = tm_lookup,
		.match = tm_match,
		.update_elem = tm_update_elem,
		.delete_elem = tm_delete_elem,
	},
};

static void *wildcard_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_wildcard *wcard =
		container_of(map, struct bpf_wildcard, map);
	struct wcard_elem *l;

	switch (((struct wildcard_key *)key)->type) {
	case BPF_WILDCARD_KEY_RULE:
		switch (wcard->algorithm) {
		case BPF_WILDCARD_F_ALGORITHM_BF:
			l = bf_lookup(wcard, key);
			break;
		case BPF_WILDCARD_F_ALGORITHM_TM:
			l = tm_lookup(wcard, key);
			break;
		}
		break;
	case BPF_WILDCARD_KEY_ELEM:
		switch (wcard->algorithm) {
		case BPF_WILDCARD_F_ALGORITHM_BF:
			l = bf_match(wcard, key);
			break;
		case BPF_WILDCARD_F_ALGORITHM_TM:
			l = tm_match(wcard, key);
			break;
		}
		break;
	default:
		return ERR_PTR(-EINVAL);
	}

	if (l)
		return l->key + round_up(wcard->map.key_size, 8);

	return ERR_PTR(-ENOENT);
}

static int wildcard_map_update_elem(struct bpf_map *map, void *key,
				    void *value, u64 map_flags)
{
	struct bpf_wildcard *wcard =
		container_of(map, struct bpf_wildcard, map);

	if (unlikely((map_flags & ~BPF_F_LOCK) > BPF_EXIST))
		/* unknown flags */
		return -EINVAL;

	WARN_ON_ONCE(!rcu_read_lock_held() && !rcu_read_lock_trace_held() &&
		     !rcu_read_lock_bh_held());

	return wcard->ops->update_elem(wcard, key, value, map_flags);
}

static int wildcard_map_delete_elem(struct bpf_map *map, void *key)
{
	struct bpf_wildcard *wcard =
		container_of(map, struct bpf_wildcard, map);

	return wcard->ops->delete_elem(wcard, key);
}

static int wildcard_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	struct bpf_wildcard *wcard =
		container_of(map, struct bpf_wildcard, map);

	return wcard->ops->get_next_key(wcard, key, next_key);
}

static void wildcard_map_free(struct bpf_map *map)
{
	struct bpf_wildcard *wcard =
		container_of(map, struct bpf_wildcard, map);

	lockdep_unregister_key(&wcard->lockdep_key);
	wcard->ops->free(wcard);
	bpf_map_area_free(wcard);
}

static int wildcard_map_alloc_check(union bpf_attr *attr)
{
	struct wildcard_desc *desc = attr->map_extra_data;
	struct wildcard_rule_desc *rule_desc;
	unsigned int algorithm;
	unsigned int i, j;
	u64 flags_mask;
	bool prealloc;
	u32 tot_size;

	if (!bpf_capable())
		return -EPERM;

	/* not implemented, yet, sorry */
	prealloc = !(attr->map_flags & BPF_F_NO_PREALLOC);
	if (prealloc)
		return -ENOTSUPP;

	if (attr->max_entries == 0 || attr->key_size == 0 ||
	    attr->value_size == 0)
		return -EINVAL;

	if ((u64)attr->key_size + attr->value_size >= KMALLOC_MAX_SIZE -
	   sizeof(struct wcard_elem))
		/* if key_size + value_size is bigger, the user space won't be
		 * able to access the elements via bpf syscall. This check
		 * also makes sure that the elem_size doesn't overflow and it's
		 * kmalloc-able later in wildcard_map_update_elem()
		 */
		return -E2BIG;

	algorithm = BPF_WILDCARD_ALGORITHM(attr->map_extra);
	if (algorithm >= BPF_WILDCARD_F_ALGORITHM_MAX)
		return -EINVAL;

	switch (algorithm) {
	case BPF_WILDCARD_F_ALGORITHM_BF:
		flags_mask = BPF_WILDCARD_F_PRIORITY;
		break;
	case BPF_WILDCARD_F_ALGORITHM_TM:
		flags_mask = BPF_WILDCARD_F_PRIORITY |
			     BPF_WILDCARD_F_TM_STATIC_POOL |
			     BPF_WILDCARD_F_TM_POOL_LIST;
		break;
	}
	if (attr->map_extra & ~BPF_WILDCARD_F_ALGORITHM_MASK & ~flags_mask)
		return -EINVAL;

	if (!desc || !desc->n_rules)
		return -EINVAL;

	tot_size = 0;
	for (i = 0; i < !desc->n_rules; i++) {
		rule_desc = &desc->rule_desc[i];

		switch (rule_desc->type) {
			case BPF_WILDCARD_RULE_PREFIX:
			case BPF_WILDCARD_RULE_RANGE:
			case BPF_WILDCARD_RULE_MATCH:
				break;
			default:
				return -EINVAL;
		}

		switch (rule_desc->size) {
			case 1:
			case 2:
			case 4:
			case 8:
				break;
			case 16:
				if (rule_desc->type == BPF_WILDCARD_RULE_RANGE)
					return -EINVAL;
				break;
			default:
				return -EINVAL;
		}

		tot_size += rule_desc->size;

		for (j = 0; j < rule_desc->n_prefixes; j++) {
			if (rule_desc->prefixes[j] > rule_desc->size)
				return -EINVAL;
		}
	}
	if (tot_size > BPF_WILDCARD_MAX_TOTAL_RULE_SIZE)
		return -EINVAL;

	return 0;
}

static struct bpf_map *wildcard_map_alloc(union bpf_attr *attr)
{
	int numa_node = bpf_map_attr_numa_node(attr);
	struct bpf_wildcard *wcard;
	u64 data_size;
	int err;

	data_size = sizeof(*wcard) + attr->map_extra_data_size;
	wcard = bpf_map_area_alloc(data_size, numa_node);
	if (!wcard)
		return ERR_PTR(-ENOMEM);

	/* Copy and release the map_extra_data field */
	wcard->desc = (void *)(wcard + 1);
	memcpy(wcard->desc, attr->map_extra_data, attr->map_extra_data_size);
	kfree(attr->map_extra_data);
	attr->map_extra_data = 0;

	lockdep_register_key(&wcard->lockdep_key);

	bpf_map_init_from_attr(&wcard->map, attr);

	wcard->prealloc = !(wcard->map.map_flags & BPF_F_NO_PREALLOC);
	wcard->priority = !!(attr->map_extra & BPF_WILDCARD_F_PRIORITY);

	wcard->elem_size = sizeof(struct wcard_elem) +
			  round_up(wcard->map.key_size, 8) +
			  round_up(wcard->map.value_size, 8);

	wcard->algorithm = BPF_WILDCARD_ALGORITHM(attr->map_extra);
	wcard->ops = &wildcard_algorithms[wcard->algorithm];

	err = wcard->ops->alloc(wcard, attr);
	if (err < 0)
		goto free_wcard;

	return &wcard->map;

free_wcard:
	wildcard_map_free(&wcard->map);
	return ERR_PTR(err);
}

BTF_ID_LIST_SINGLE(bpf_wildcard_map_btf_ids, struct, bpf_wildcard)
const struct bpf_map_ops wildcard_map_ops = {
	.map_meta_equal = bpf_map_meta_equal,
	.map_alloc_check = wildcard_map_alloc_check,
	.map_alloc = wildcard_map_alloc,
	.map_free = wildcard_map_free,
	.map_lookup_elem = wildcard_map_lookup_elem,
	.map_update_elem = wildcard_map_update_elem,
	.map_delete_elem = wildcard_map_delete_elem,
	.map_get_next_key = wildcard_map_get_next_key,
	.map_btf_id = &bpf_wildcard_map_btf_ids[0],
};
