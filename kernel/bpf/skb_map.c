// SPDX-License-Identifier: GPL-2.0
/*
 * skb_map.c: BPF skb queue map
 *
 * Copyright (C) 2022, Bytedance, Cong Wang <cong.wang@bytedance.com>
 */
#include <linux/bpf.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/capability.h>
#include <linux/rbtree.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <net/sch_generic.h>

#define SKB_MAP_CREATE_FLAG_MASK \
	(BPF_F_NUMA_NODE | BPF_F_ACCESS_MASK)

struct bpf_skb_map {
	struct bpf_map map;
	struct rb_root root;
	raw_spinlock_t lock;
	struct list_head list;
	atomic_t count;
};

struct skb_map_cb {
	struct qdisc_skb_cb qdisc_cb;
	u64 rank;
};

static struct skb_map_cb *skb_map_cb(const struct sk_buff *skb)
{
        struct skb_map_cb *cb = (struct skb_map_cb *)skb->cb;

        BUILD_BUG_ON(sizeof(*cb) > sizeof_field(struct sk_buff, cb));
        return cb;
}

static DEFINE_SPINLOCK(skb_map_lock);
static LIST_HEAD(skb_map_list);

static struct bpf_skb_map *bpf_skb_map(struct bpf_map *map)
{
	return container_of(map, struct bpf_skb_map, map);
}

#define SKB_MAP_MAX_SZ 2048

/* Called from syscall */
static int skb_map_alloc_check(union bpf_attr *attr)
{
	if (!bpf_capable())
		return -EPERM;

	/* check sanity of attributes */
	if (attr->max_entries == 0 || attr->key_size != 8 ||
	    attr->value_size != 0 ||
	    attr->map_flags & ~SKB_MAP_CREATE_FLAG_MASK ||
	    !bpf_map_flags_access_ok(attr->map_flags))
		return -EINVAL;

	if (attr->value_size > KMALLOC_MAX_SIZE)
		/* if value_size is bigger, the user space won't be able to
		 * access the elements.
		 */
		return -E2BIG;

	if (attr->max_entries > SKB_MAP_MAX_SZ)
		return -E2BIG;

	return 0;
}

static struct bpf_map *skb_map_alloc(union bpf_attr *attr)
{
	int numa_node = bpf_map_attr_numa_node(attr);
	struct bpf_skb_map *rb;

	rb = bpf_map_area_alloc(sizeof(*rb), numa_node);
	if (!rb)
		return ERR_PTR(-ENOMEM);

	memset(rb, 0, sizeof(*rb));
	bpf_map_init_from_attr(&rb->map, attr);
	raw_spin_lock_init(&rb->lock);
	rb->root = RB_ROOT;
	atomic_set(&rb->count, 0);
	spin_lock(&skb_map_lock);
	list_add_tail_rcu(&rb->list, &skb_map_list);
	spin_unlock(&skb_map_lock);
	return &rb->map;
}

static void skb_map_free(struct bpf_map *map)
{
	struct bpf_skb_map *rb = bpf_skb_map(map);

	spin_lock(&skb_map_lock);
	list_del_rcu(&rb->list);
	spin_unlock(&skb_map_lock);
	skb_rbtree_purge(&rb->root);
	bpf_map_area_free(rb);
}

static struct sk_buff *skb_rb_find(struct rb_root *root, u64 rank)
{
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent = NULL;
	struct sk_buff *skb1;

	while (*p) {
		parent = *p;
		skb1 = rb_to_skb(parent);
		if (rank < skb_map_cb(skb1)->rank)
			p = &parent->rb_left;
		else if (rank > skb_map_cb(skb1)->rank)
			p = &parent->rb_right;
		else
			return skb1;
	}
	return NULL;
}

/* Called from syscall */
static void *skb_map_lookup_elem_sys(struct bpf_map *map, void *key)
{
	return ERR_PTR(-ENOTSUPP);
}

/* Called from eBPF program */
static void *skb_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_skb_map *rb = bpf_skb_map(map);
	u64 rank = *(u64 *) key;

	return skb_rb_find(&rb->root, rank);
}

/* Called from syscall or from eBPF program */
static int skb_map_update_elem(struct bpf_map *map, void *key, void *value,
			       u64 flags)
{
	return -ENOTSUPP;
}

/* Called from syscall or from eBPF program */
static int skb_map_delete_elem(struct bpf_map *map, void *key)
{
	struct bpf_skb_map *rb = bpf_skb_map(map);
	u64 rank = *(u64 *) key;
	struct sk_buff *skb;

	skb = skb_rb_find(&rb->root, rank);
	if (!skb)
		return -ENOENT;
	rb_erase(&skb->rbnode, &rb->root);
	consume_skb(skb);
	return 0;
}

/* Called from syscall */
static int skb_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	struct bpf_skb_map *rb = bpf_skb_map(map);
	struct sk_buff *skb;
	u64 rank;

	if (!key) {
		skb = skb_rb_first(&rb->root);
		if (!skb)
			return -ENOENT;
	}
	rank = *(u64 *) key;
	skb = skb_rb_find(&rb->root, rank);
	if (!skb)
		return -ENOENT;
	skb = skb_rb_next(skb);
	if (!skb)
		return 0;
	*(u64 *) next_key = skb_map_cb(skb)->rank;
	return 0;
}

static int bpf_for_each_skb_map(struct bpf_map *map, bpf_callback_t callback_fn,
				void *callback_ctx, u64 flags)
{
	struct bpf_skb_map *rb = bpf_skb_map(map);
	struct sk_buff *skb;
	u32 num_elems = 0;
	u64 ret = 0;
	u64 key;

	if (flags != 0)
		return -EINVAL;

	skb_rbtree_walk(skb, &rb->root) {
		num_elems++;
		key = skb_map_cb(skb)->rank;
		ret = callback_fn((u64)(long)map, (u64)(long)&key,
				  (u64)(long)skb, (u64)(long)callback_ctx, 0);
		/* return value: 0 - continue, 1 - stop and return */
		if (ret)
			break;
	}

	return num_elems;
}

BTF_ID_LIST_SINGLE(skb_map_btf_ids, struct, bpf_skb_map)
const struct bpf_map_ops skb_map_ops = {
	.map_meta_equal = bpf_map_meta_equal,
	.map_alloc_check = skb_map_alloc_check,
	.map_alloc = skb_map_alloc,
	.map_free = skb_map_free,
	.map_lookup_elem_sys_only = skb_map_lookup_elem_sys,
	.map_lookup_elem = skb_map_lookup_elem,
	.map_update_elem = skb_map_update_elem,
	.map_delete_elem = skb_map_delete_elem,
	.map_get_next_key = skb_map_get_next_key,
	.map_set_for_each_callback_args = map_set_for_each_callback_args,
	.map_for_each_callback = bpf_for_each_skb_map,
	.map_btf_id = &skb_map_btf_ids[0],
};

static void skb_rb_push(struct rb_root *root, struct sk_buff *skb)
{
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent = NULL;
	struct sk_buff *skb1;

	while (*p) {
		parent = *p;
		skb1 = rb_to_skb(parent);
		if (skb_map_cb(skb)->rank < skb_map_cb(skb1)->rank)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}
	rb_link_node(&skb->rbnode, parent, p);
	rb_insert_color(&skb->rbnode, root);
}

BPF_CALL_2(bpf_skb_map_pop, struct bpf_map *, map, u64, key)
{
	struct bpf_skb_map *rb = bpf_skb_map(map);
	struct sk_buff *skb;
	unsigned long flags;

	raw_spin_lock_irqsave(&rb->lock, flags);
	skb = skb_map_lookup_elem(map, &key);
	if (!skb) {
		raw_spin_unlock_irqrestore(&rb->lock, flags);
		return (unsigned long)NULL;
	}
	rb_erase(&skb->rbnode, &rb->root);
	raw_spin_unlock_irqrestore(&rb->lock, flags);
	consume_skb(skb);
	atomic_dec(&rb->count);
	return (unsigned long)skb;
}

static const struct bpf_func_proto bpf_skb_map_pop_proto = {
	.func		= bpf_skb_map_pop,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_ANYTHING,
};

BPF_CALL_3(bpf_skb_map_push, struct bpf_map *, map, struct sk_buff *, skb, u64, key)
{
	struct bpf_skb_map *rb = bpf_skb_map(map);
	unsigned long flags;

	if (atomic_inc_return(&rb->count) > rb->map.max_entries)
		return -ENOBUFS;
	skb = skb_get(skb);
	skb_map_cb(skb)->rank = key;
	raw_spin_lock_irqsave(&rb->lock, flags);
	skb_rb_push(&rb->root, skb);
	raw_spin_unlock_irqrestore(&rb->lock, flags);
	return 0;
}

static const struct bpf_func_proto bpf_skb_map_push_proto = {
	.func		= bpf_skb_map_push,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_CTX,
	.arg3_type	= ARG_ANYTHING,
};

static void skb_map_flush(struct bpf_skb_map *rb, struct net_device *dev)
{
	struct rb_node *p = rb_first(&rb->root);

	while (p) {
		struct sk_buff *skb = rb_entry(p, struct sk_buff, rbnode);

		p = rb_next(p);
		if (skb->dev == dev) {
			rb_erase(&skb->rbnode, &rb->root);
			kfree_skb(skb);
		}
	}
}

static int skb_map_notification(struct notifier_block *notifier,
				ulong event, void *ptr)
{
	struct net_device *netdev = netdev_notifier_info_to_dev(ptr);
	struct bpf_skb_map *rb;

        switch (event) {
        case NETDEV_DOWN:
		rcu_read_lock();
		list_for_each_entry_rcu(rb, &skb_map_list, list)
			skb_map_flush(rb, netdev);
		rcu_read_unlock();
		break;
	}
	return NOTIFY_OK;
}

static struct notifier_block skb_map_notifier = {
	.notifier_call = skb_map_notification,
};

static int __init skb_map_init(void)
{
	return register_netdevice_notifier(&skb_map_notifier);
}

subsys_initcall(skb_map_init);
