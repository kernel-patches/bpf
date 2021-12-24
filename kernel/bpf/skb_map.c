// SPDX-License-Identifier: GPL-2.0
/*
 * skb_map.c: BPF skb queue map
 *
 * Copyright (C) 2021, Bytedance, Cong Wang <cong.wang@bytedance.com>
 */
#include <linux/bpf.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/capability.h>
#include <linux/priority_queue.h>

#define SKB_MAP_CREATE_FLAG_MASK \
	(BPF_F_NUMA_NODE | BPF_F_ACCESS_MASK)

struct bpf_skb_map {
	struct bpf_map map;
	struct pq_root root;
	raw_spinlock_t lock;
	struct list_head list;
	atomic_t count;
};

struct skb_map_node {
	struct pq_node node;
	u64 key;
	struct sk_buff *skb;
};

static DEFINE_SPINLOCK(skb_map_lock);
static LIST_HEAD(skb_map_list);

static struct bpf_skb_map *bpf_skb_map(struct bpf_map *map)
{
	return container_of(map, struct bpf_skb_map, map);
}

#define SKB_MAP_MAX_SZ 1024

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

static bool skb_map_cmp(struct pq_node *l, struct pq_node *r)
{
	struct skb_map_node *lnode, *rnode;

	lnode = container_of(l, struct skb_map_node, node);
	rnode = container_of(r, struct skb_map_node, node);

	return lnode->key < rnode->key;
}

static struct bpf_map *skb_map_alloc(union bpf_attr *attr)
{
	int numa_node = bpf_map_attr_numa_node(attr);
	struct bpf_skb_map *pq;

	pq = bpf_map_area_alloc(sizeof(*pq), numa_node);
	if (!pq)
		return ERR_PTR(-ENOMEM);

	memset(pq, 0, sizeof(*pq));
	bpf_map_init_from_attr(&pq->map, attr);
	raw_spin_lock_init(&pq->lock);
	pq_root_init(&pq->root, skb_map_cmp);
	atomic_set(&pq->count, 0);
	spin_lock(&skb_map_lock);
	list_add_tail_rcu(&pq->list, &skb_map_list);
	spin_unlock(&skb_map_lock);
	return &pq->map;
}

static void skb_flush(struct pq_node *n)
{
	struct sk_buff *skb = container_of(n, struct sk_buff, pqnode);

	kfree_skb(skb);
}

static void skb_map_free(struct bpf_map *map)
{
	struct bpf_skb_map *pq = bpf_skb_map(map);

	spin_lock(&skb_map_lock);
	list_del_rcu(&pq->list);
	spin_unlock(&skb_map_lock);
	pq_flush(&pq->root, skb_flush);
	bpf_map_area_free(pq);
}

static struct skb_map_node *alloc_skb_map_node(struct bpf_skb_map *pq)
{
	return bpf_map_kmalloc_node(&pq->map, sizeof(struct skb_map_node),
				     GFP_ATOMIC | __GFP_NOWARN,
				     pq->map.numa_node);
}

/* Called from syscall or from eBPF program */
static void *skb_map_lookup_elem(struct bpf_map *map, void *key)
{
	return ERR_PTR(-ENOTSUPP);
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
	return -ENOTSUPP;
}

/* Called from syscall */
static int skb_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	return -ENOTSUPP;
}

static int skb_map_btf_id;
const struct bpf_map_ops skb_queue_map_ops = {
	.map_meta_equal = bpf_map_meta_equal,
	.map_alloc_check = skb_map_alloc_check,
	.map_alloc = skb_map_alloc,
	.map_free = skb_map_free,
	.map_lookup_elem = skb_map_lookup_elem,
	.map_update_elem = skb_map_update_elem,
	.map_delete_elem = skb_map_delete_elem,
	.map_get_next_key = skb_map_get_next_key,
	.map_btf_name = "bpf_skb_map",
	.map_btf_id = &skb_map_btf_id,
};

int skb_map_enqueue(struct sk_buff *skb, struct bpf_map *map, u64 key)
{
	struct bpf_skb_map *pq = bpf_skb_map(map);
	struct skb_map_node *n;
	unsigned long flags;

	if (atomic_inc_return(&pq->count) > pq->map.max_entries)
		return -ENOBUFS;
	n = alloc_skb_map_node(pq);
	if (!n)
		return -ENOMEM;
	n->key = key;
	n->skb = skb_get(skb);
	raw_spin_lock_irqsave(&pq->lock, flags);
	pq_push(&pq->root, &n->node);
	raw_spin_unlock_irqrestore(&pq->lock, flags);
	return 0;

}

struct sk_buff *skb_map_dequeue(struct bpf_map *map)
{
	struct bpf_skb_map *pq = bpf_skb_map(map);
	struct skb_map_node *n;
	struct pq_node *node;
	unsigned long flags;

	raw_spin_lock_irqsave(&pq->lock, flags);
	node = pq_pop(&pq->root);
	if (!node) {
		raw_spin_unlock_irqrestore(&pq->lock, flags);
		return NULL;
	}
	raw_spin_unlock_irqrestore(&pq->lock, flags);
	n = container_of(node, struct skb_map_node, node);
	consume_skb(n->skb);
	atomic_dec(&pq->count);
	return n->skb;
}

static void skb_map_flush(struct bpf_skb_map *pq, struct net_device *dev)
{
	struct pq_root *root = &pq->root;
	struct rb_node *node, *next;

	for (node = rb_first(&root->rb_root.rb_root);
	     next = node ? rb_next(node) : NULL, node != NULL;
	     node = next) {
		struct pq_node *pqe;
		struct sk_buff *skb;

		pqe = rb_entry(node, struct pq_node, rb_node);
		skb = container_of(pqe, struct sk_buff, pqnode);
		if (skb->dev == dev)
			kfree_skb(skb);
        }
}

static int skb_map_notification(struct notifier_block *notifier,
				ulong event, void *ptr)
{
	struct net_device *netdev = netdev_notifier_info_to_dev(ptr);
	struct bpf_skb_map *pq;

        switch (event) {
        case NETDEV_DOWN:
		rcu_read_lock();
		list_for_each_entry_rcu(pq, &skb_map_list, list)
			skb_map_flush(pq, netdev);
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
