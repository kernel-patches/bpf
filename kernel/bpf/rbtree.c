// SPDX-License-Identifier: GPL-2.0
/*
 * rbtree.c: eBPF rbtree map
 *
 * Copyright (C) 2022, ByteDance, Cong Wang <cong.wang@bytedance.com>
 */
#include <linux/bpf.h>
#include <linux/slab.h>
#include <linux/capability.h>
#include <linux/rbtree.h>
#include <linux/btf_ids.h>
#include <linux/bpf_mem_alloc.h>
#include <linux/math.h>
#include <linux/seq_file.h>
#include "map_in_map.h"

#define RBTREE_CREATE_FLAG_MASK \
	(BPF_F_NUMA_NODE | BPF_F_ACCESS_MASK)

/* each rbtree element is struct rbtree_elem + key + value */
struct rbtree_elem {
	struct rb_node rbnode;
	char key[] __aligned(8);
};

struct rbtree_map {
	struct bpf_map map;
	struct bpf_mem_alloc ma;
	raw_spinlock_t lock;
	struct rb_root root;
	atomic_t nr_entries;
};

#define rb_to_elem(rb) rb_entry_safe(rb, struct rbtree_elem, rbnode)
#define elem_rb_first(root) rb_to_elem(rb_first(root))
#define elem_rb_last(root)  rb_to_elem(rb_last(root))
#define elem_rb_next(e)   rb_to_elem(rb_next(&(e)->rbnode))
#define rbtree_walk_safe(e, tmp, root)					\
		for (e = elem_rb_first(root);				\
		     tmp = e ? elem_rb_next(e) : NULL, (e != NULL);	\
		     e = tmp)

static struct rbtree_map *rbtree_map(struct bpf_map *map)
{
	return container_of(map, struct rbtree_map, map);
}

/* Called from syscall */
static int rbtree_map_alloc_check(union bpf_attr *attr)
{
	if (!bpf_capable())
		return -EPERM;

	/* check sanity of attributes */
	if (attr->max_entries == 0 ||
	    attr->map_flags & ~RBTREE_CREATE_FLAG_MASK ||
	    !bpf_map_flags_access_ok(attr->map_flags))
		return -EINVAL;

	if (attr->value_size > KMALLOC_MAX_SIZE)
		/* if value_size is bigger, the user space won't be able to
		 * access the elements.
		 */
		return -E2BIG;

	return 0;
}

static struct bpf_map *rbtree_map_alloc(union bpf_attr *attr)
{
	int numa_node = bpf_map_attr_numa_node(attr);
	struct rbtree_map *rb;
	u32 elem_size;
	int err;

	rb = bpf_map_area_alloc(sizeof(*rb), numa_node);
	if (!rb)
		return ERR_PTR(-ENOMEM);

	memset(rb, 0, sizeof(*rb));
	bpf_map_init_from_attr(&rb->map, attr);
	raw_spin_lock_init(&rb->lock);
	rb->root = RB_ROOT;
	atomic_set(&rb->nr_entries, 0);

	elem_size = sizeof(struct rbtree_elem) +
			  round_up(rb->map.key_size, 8);
	elem_size += round_up(rb->map.value_size, 8);
	err = bpf_mem_alloc_init(&rb->ma, elem_size, false);
	if (err) {
		bpf_map_area_free(rb);
		return ERR_PTR(err);
	}
	return &rb->map;
}

static void check_and_free_fields(struct rbtree_map *rb,
				  struct rbtree_elem *elem)
{
	void *map_value = elem->key + round_up(rb->map.key_size, 8);

	if (map_value_has_kptrs(&rb->map))
		bpf_map_free_kptrs(&rb->map, map_value);
}

static void rbtree_map_purge(struct bpf_map *map)
{
	struct rbtree_map *rb = rbtree_map(map);
	struct rbtree_elem *e, *tmp;

	rbtree_walk_safe(e, tmp, &rb->root) {
		rb_erase(&e->rbnode, &rb->root);
		check_and_free_fields(rb, e);
		bpf_mem_cache_free(&rb->ma, e);
	}
}

/* Called when map->refcnt goes to zero, either from workqueue or from syscall */
static void rbtree_map_free(struct bpf_map *map)
{
	struct rbtree_map *rb = rbtree_map(map);
	unsigned long flags;

	raw_spin_lock_irqsave(&rb->lock, flags);
	rbtree_map_purge(map);
	raw_spin_unlock_irqrestore(&rb->lock, flags);
	bpf_mem_alloc_destroy(&rb->ma);
	bpf_map_area_free(rb);
}

static struct rbtree_elem *bpf_rbtree_find(struct rb_root *root, void *key, int size)
{
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent = NULL;
	struct rbtree_elem *e;

	while (*p) {
		int ret;

		parent = *p;
		e = rb_to_elem(parent);
		ret = memcmp(key, e->key, size);
		if (ret < 0)
			p = &parent->rb_left;
		else if (ret > 0)
			p = &parent->rb_right;
		else
			return e;
	}
	return NULL;
}

/* Called from eBPF program or syscall */
static void *rbtree_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct rbtree_map *rb = rbtree_map(map);
	struct rbtree_elem *e;

	e = bpf_rbtree_find(&rb->root, key, rb->map.key_size);
	if (!e)
		return NULL;
	return e->key + round_up(rb->map.key_size, 8);
}

static int check_flags(struct rbtree_elem *old, u64 map_flags)
{
	if (old && (map_flags & ~BPF_F_LOCK) == BPF_NOEXIST)
		/* elem already exists */
		return -EEXIST;

	if (!old && (map_flags & ~BPF_F_LOCK) == BPF_EXIST)
		/* elem doesn't exist, cannot update it */
		return -ENOENT;

	return 0;
}

static void rbtree_map_insert(struct rbtree_map *rb, struct rbtree_elem *e)
{
	struct rb_root *root = &rb->root;
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent = NULL;
	struct rbtree_elem *e1;

	while (*p) {
		parent = *p;
		e1 = rb_to_elem(parent);
		if (memcmp(e->key, e1->key, rb->map.key_size) < 0)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}
	rb_link_node(&e->rbnode, parent, p);
	rb_insert_color(&e->rbnode, root);
}

/* Called from syscall or from eBPF program */
static int rbtree_map_update_elem(struct bpf_map *map, void *key, void *value,
			       u64 map_flags)
{
	struct rbtree_map *rb = rbtree_map(map);
	void *val = rbtree_map_lookup_elem(map, key);
	int ret;

	ret = check_flags(val, map_flags);
	if (ret)
		return ret;

	if (!val) {
		struct rbtree_elem *e_new;
		unsigned long flags;

		e_new = bpf_mem_cache_alloc(&rb->ma);
		if (!e_new)
			return -ENOMEM;
		val = e_new->key + round_up(rb->map.key_size, 8);
		check_and_init_map_value(&rb->map, val);
		memcpy(e_new->key, key, rb->map.key_size);
		raw_spin_lock_irqsave(&rb->lock, flags);
		rbtree_map_insert(rb, e_new);
		raw_spin_unlock_irqrestore(&rb->lock, flags);
		atomic_inc(&rb->nr_entries);
	}

	if (map_flags & BPF_F_LOCK)
		copy_map_value_locked(map, val, value, false);
	else
		copy_map_value(map, val, value);
	return 0;
}

/* Called from syscall or from eBPF program */
static int rbtree_map_delete_elem(struct bpf_map *map, void *key)
{
	struct rbtree_map *rb = rbtree_map(map);
	struct rbtree_elem *e;
	unsigned long flags;

	raw_spin_lock_irqsave(&rb->lock, flags);
	e = bpf_rbtree_find(&rb->root, key, rb->map.key_size);
	if (!e) {
		raw_spin_unlock_irqrestore(&rb->lock, flags);
		return -ENOENT;
	}
	rb_erase(&e->rbnode, &rb->root);
	raw_spin_unlock_irqrestore(&rb->lock, flags);
	check_and_free_fields(rb, e);
	bpf_mem_cache_free(&rb->ma, e);
	atomic_dec(&rb->nr_entries);
	return 0;
}

/* Called from syscall or from eBPF program */
static int rbtree_map_pop_elem(struct bpf_map *map, void *value)
{
	struct rbtree_map *rb = rbtree_map(map);
	struct rbtree_elem *e = elem_rb_first(&rb->root);
	unsigned long flags;
	void *val;

	if (!e)
		return -ENOENT;
	raw_spin_lock_irqsave(&rb->lock, flags);
	rb_erase(&e->rbnode, &rb->root);
	raw_spin_unlock_irqrestore(&rb->lock, flags);
	val = e->key + round_up(rb->map.key_size, 8);
	copy_map_value(map, value, val);
	check_and_free_fields(rb, e);
	bpf_mem_cache_free(&rb->ma, e);
	atomic_dec(&rb->nr_entries);
	return 0;
}

/* Called from syscall */
static int rbtree_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	struct rbtree_map *rb = rbtree_map(map);
	struct rbtree_elem *e;

	if (!key) {
		e = elem_rb_first(&rb->root);
		if (!e)
			return -ENOENT;
		goto found;
	}
	e = bpf_rbtree_find(&rb->root, key, rb->map.key_size);
	if (!e)
		return -ENOENT;
	e = elem_rb_next(e);
	if (!e)
		return 0;
found:
	memcpy(next_key, e->key, map->key_size);
	return 0;
}

static int bpf_for_each_rbtree_map(struct bpf_map *map,
				   bpf_callback_t callback_fn,
				   void *callback_ctx, u64 flags)
{
	struct rbtree_map *rb = rbtree_map(map);
	struct rbtree_elem *e, *tmp;
	void *key, *value;
	u32 num_elems = 0;
	u64 ret = 0;

	if (flags != 0)
		return -EINVAL;

	rbtree_walk_safe(e, tmp, &rb->root) {
		num_elems++;
		key = e->key;
		value = key + round_up(rb->map.key_size, 8);
		ret = callback_fn((u64)(long)map, (u64)(long)key, (u64)(long)value,
				  (u64)(long)callback_ctx, 0);
		/* return value: 0 - continue, 1 - stop and return */
		if (ret)
			break;
	}

	return num_elems;
}

struct rbtree_map_seq_info {
	struct bpf_map *map;
	struct rbtree_map *rb;
};

static void *rbtree_map_seq_find_next(struct rbtree_map_seq_info *info,
				      struct rbtree_elem *prev_elem)
{
	const struct rbtree_map *rb = info->rb;
	struct rbtree_elem *elem;

	/* try to find next elem in the same bucket */
	if (prev_elem) {
		elem = elem_rb_next(prev_elem);
		if (elem)
			return elem;
		return NULL;
	}

	return elem_rb_first(&rb->root);
}

static void *rbtree_map_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct rbtree_map_seq_info *info = seq->private;

	if (*pos == 0)
		++*pos;

	/* pairs with rbtree_map_seq_stop */
	rcu_read_lock();
	return rbtree_map_seq_find_next(info, NULL);
}

static void *rbtree_map_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct rbtree_map_seq_info *info = seq->private;

	++*pos;
	return rbtree_map_seq_find_next(info, v);
}

static int rbtree_map_seq_show(struct seq_file *seq, void *v)
{
	struct rbtree_map_seq_info *info = seq->private;
	struct bpf_iter__bpf_map_elem ctx = {};
	struct rbtree_elem *elem = v;
	struct bpf_iter_meta meta;
	struct bpf_prog *prog;

	meta.seq = seq;
	prog = bpf_iter_get_info(&meta, !elem);
	if (!prog)
		return 0;

	ctx.meta = &meta;
	ctx.map = info->map;
	if (elem) {
		ctx.key = elem->key;
		ctx.value = elem->key + round_up(info->map->key_size, 8);
	}

	return bpf_iter_run_prog(prog, &ctx);
}

static void rbtree_map_seq_stop(struct seq_file *seq, void *v)
{
	if (!v)
		(void)rbtree_map_seq_show(seq, NULL);

	/* pairs with rbtree_map_seq_start */
	rcu_read_unlock();
}

static const struct seq_operations rbtree_map_seq_ops = {
	.start	= rbtree_map_seq_start,
	.next	= rbtree_map_seq_next,
	.stop	= rbtree_map_seq_stop,
	.show	= rbtree_map_seq_show,
};

static int rbtree_map_init_seq_private(void *priv_data,
				       struct bpf_iter_aux_info *aux)
{
	struct rbtree_map_seq_info *info = priv_data;

	bpf_map_inc_with_uref(aux->map);
	info->map = aux->map;
	info->rb = rbtree_map(info->map);
	return 0;
}

static void rbtree_map_fini_seq_private(void *priv_data)
{
	struct rbtree_map_seq_info *info = priv_data;

	bpf_map_put_with_uref(info->map);
}

static const struct bpf_iter_seq_info rbtree_map_iter_seq_info = {
	.seq_ops		= &rbtree_map_seq_ops,
	.init_seq_private	= rbtree_map_init_seq_private,
	.fini_seq_private	= rbtree_map_fini_seq_private,
	.seq_priv_size		= sizeof(struct rbtree_map_seq_info),
};

BTF_ID_LIST_SINGLE(rbtree_map_btf_ids, struct, rbtree_map)
const struct bpf_map_ops rbtree_map_ops = {
	.map_meta_equal = bpf_map_meta_equal,
	.map_alloc_check = rbtree_map_alloc_check,
	.map_alloc = rbtree_map_alloc,
	.map_free = rbtree_map_free,
	.map_lookup_elem = rbtree_map_lookup_elem,
	.map_update_elem = rbtree_map_update_elem,
	.map_delete_elem = rbtree_map_delete_elem,
	.map_pop_elem = rbtree_map_pop_elem,
	.map_get_next_key = rbtree_map_get_next_key,
	.map_set_for_each_callback_args = map_set_for_each_callback_args,
	.map_for_each_callback = bpf_for_each_rbtree_map,
	.map_btf_id = &rbtree_map_btf_ids[0],
	.iter_seq_info = &rbtree_map_iter_seq_info,
};

static struct bpf_map *rbtree_map_in_map_alloc(union bpf_attr *attr)
{
	struct bpf_map *map, *inner_map_meta;

	inner_map_meta = bpf_map_meta_alloc(attr->inner_map_fd);
	if (IS_ERR(inner_map_meta))
		return inner_map_meta;

	map = rbtree_map_alloc(attr);
	if (IS_ERR(map)) {
		bpf_map_meta_free(inner_map_meta);
		return map;
	}

	map->inner_map_meta = inner_map_meta;
	return map;
}

static void *fd_rbtree_map_get_ptr(const struct bpf_map *map, struct rbtree_elem *e)
{
	return *(void **)(e->key + roundup(map->key_size, 8));
}

static void rbtree_map_in_map_purge(struct bpf_map *map)
{
	struct rbtree_map *rb = rbtree_map(map);
	struct rbtree_elem *e, *tmp;

	rbtree_walk_safe(e, tmp, &rb->root) {
		void *ptr = fd_rbtree_map_get_ptr(map, e);

		map->ops->map_fd_put_ptr(ptr);
	}
}

static void rbtree_map_in_map_free(struct bpf_map *map)
{
	struct rbtree_map *rb = rbtree_map(map);

	bpf_map_meta_free(map->inner_map_meta);
	rbtree_map_in_map_purge(map);
	bpf_map_area_free(rb);
}

/* Called from eBPF program */
static void *rbtree_map_in_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_map **inner_map = rbtree_map_lookup_elem(map, key);

	if (!inner_map)
		return NULL;

	return READ_ONCE(*inner_map);
}

static int rbtree_map_in_map_alloc_check(union bpf_attr *attr)
{
	if (attr->value_size != sizeof(u32))
		return -EINVAL;
	return rbtree_map_alloc_check(attr);
}

/* Called from eBPF program */
static int rbtree_map_in_map_pop_elem(struct bpf_map *map, void *value)
{
	struct rbtree_map *rb = rbtree_map(map);
	struct rbtree_elem *e = elem_rb_first(&rb->root);
	struct bpf_map **inner_map;
	unsigned long flags;

	if (!e)
		return -ENOENT;
	raw_spin_lock_irqsave(&rb->lock, flags);
	rb_erase(&e->rbnode, &rb->root);
	raw_spin_unlock_irqrestore(&rb->lock, flags);
	inner_map = fd_rbtree_map_get_ptr(map, e);
	*(void **)value = *inner_map;
	bpf_mem_cache_free(&rb->ma, e);
	atomic_dec(&rb->nr_entries);
	return 0;
}

/* only called from syscall */
int bpf_fd_rbtree_map_pop_elem(struct bpf_map *map, void *value)
{
	struct bpf_map *ptr;
	int ret = 0;

	if (!map->ops->map_fd_sys_lookup_elem)
		return -ENOTSUPP;

	rcu_read_lock();
	ret = rbtree_map_in_map_pop_elem(map, &ptr);
	if (!ret)
		*(u32 *)value = map->ops->map_fd_sys_lookup_elem(ptr);
	else
		ret = -ENOENT;
	rcu_read_unlock();

	return ret;
}

/* only called from syscall */
int bpf_fd_rbtree_map_lookup_elem(struct bpf_map *map, void *key, u32 *value)
{
	void **ptr;
	int ret = 0;

	if (!map->ops->map_fd_sys_lookup_elem)
		return -ENOTSUPP;

	rcu_read_lock();
	ptr = rbtree_map_lookup_elem(map, key);
	if (ptr)
		*value = map->ops->map_fd_sys_lookup_elem(READ_ONCE(*ptr));
	else
		ret = -ENOENT;
	rcu_read_unlock();

	return ret;
}

/* only called from syscall */
int bpf_fd_rbtree_map_update_elem(struct bpf_map *map, struct file *map_file,
				  void *key, void *value, u64 map_flags)
{
	void *ptr;
	int ret;
	u32 ufd = *(u32 *)value;

	ptr = map->ops->map_fd_get_ptr(map, map_file, ufd);
	if (IS_ERR(ptr))
		return PTR_ERR(ptr);

	ret = rbtree_map_update_elem(map, key, &ptr, map_flags);
	if (ret)
		map->ops->map_fd_put_ptr(ptr);

	return ret;
}

const struct bpf_map_ops rbtree_map_in_map_ops = {
	.map_alloc_check = rbtree_map_in_map_alloc_check,
	.map_alloc = rbtree_map_in_map_alloc,
	.map_free = rbtree_map_in_map_free,
	.map_get_next_key = rbtree_map_get_next_key,
	.map_lookup_elem = rbtree_map_in_map_lookup_elem,
	.map_update_elem = rbtree_map_update_elem,
	.map_pop_elem = rbtree_map_in_map_pop_elem,
	.map_delete_elem = rbtree_map_delete_elem,
	.map_fd_get_ptr = bpf_map_fd_get_ptr,
	.map_fd_put_ptr = bpf_map_fd_put_ptr,
	.map_fd_sys_lookup_elem = bpf_map_fd_sys_lookup_elem,
	.map_check_btf = map_check_no_btf,
	.map_btf_id = &rbtree_map_btf_ids[0],
};

