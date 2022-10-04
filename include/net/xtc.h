/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2022 Isovalent */
#ifndef __NET_XTC_H
#define __NET_XTC_H

#include <linux/idr.h>
#include <linux/bpf.h>

#include <net/sch_generic.h>

#define XTC_MAX_ENTRIES 30
/* Adds 1 NULL entry. */
#define XTC_MAX	(XTC_MAX_ENTRIES + 1)

struct xtc_entry {
	struct bpf_prog_array_item items[XTC_MAX] ____cacheline_aligned;
	struct xtc_entry_pair *parent;
};

struct mini_Qdisc;

struct xtc_entry_pair {
	struct rcu_head		rcu;
	struct idr		idr;
	struct mini_Qdisc	*miniq;
	struct xtc_entry	a;
	struct xtc_entry	b;
};

struct bpf_tc_link {
	struct bpf_link link;
	struct net_device *dev;
	u32 priority;
	u32 location;
};

static inline void xtc_set_ingress(struct sk_buff *skb, bool ingress)
{
#ifdef CONFIG_NET_XGRESS
	skb->tc_at_ingress = ingress;
#endif
}

#ifdef CONFIG_NET_XGRESS
void xtc_inc(void);
void xtc_dec(void);

static inline void
dev_xtc_entry_update(struct net_device *dev, struct xtc_entry *entry,
		     bool ingress)
{
	ASSERT_RTNL();
	if (ingress)
		rcu_assign_pointer(dev->xtc_ingress, entry);
	else
		rcu_assign_pointer(dev->xtc_egress, entry);
	synchronize_rcu();
}

static inline struct xtc_entry *dev_xtc_entry_peer(const struct xtc_entry *entry)
{
	if (entry == &entry->parent->a)
		return &entry->parent->b;
	else
		return &entry->parent->a;
}

static inline struct xtc_entry *dev_xtc_entry_create(void)
{
	struct xtc_entry_pair *pair = kzalloc(sizeof(*pair), GFP_KERNEL);

	if (pair) {
		pair->a.parent = pair;
		pair->b.parent = pair;
		idr_init(&pair->idr);
		return &pair->a;
	}
	return NULL;
}

static inline struct xtc_entry *dev_xtc_entry_fetch(struct net_device *dev,
						    bool ingress, bool *created)
{
	struct xtc_entry *entry = ingress ?
		rcu_dereference_rtnl(dev->xtc_ingress) :
		rcu_dereference_rtnl(dev->xtc_egress);

	*created = false;
	if (!entry) {
		entry = dev_xtc_entry_create();
		if (!entry)
			return NULL;
		*created = true;
	}
	return entry;
}

static inline void dev_xtc_entry_clear(struct xtc_entry *entry)
{
	memset(entry->items, 0, sizeof(entry->items));
}

static inline int dev_xtc_entry_prio_new(struct xtc_entry *entry, u32 prio,
					 struct bpf_prog *prog)
{
	int ret;

	if (prio == 0)
		prio = 1;
	ret = idr_alloc_u32(&entry->parent->idr, prog, &prio, U32_MAX,
			    GFP_KERNEL);
	return ret < 0 ? ret : prio;
}

static inline void dev_xtc_entry_prio_set(struct xtc_entry *entry, u32 prio,
					  struct bpf_prog *prog)
{
	idr_replace(&entry->parent->idr, prog, prio);
}

static inline void dev_xtc_entry_prio_del(struct xtc_entry *entry, u32 prio)
{
	idr_remove(&entry->parent->idr, prio);
}

static inline void dev_xtc_entry_free(struct xtc_entry *entry)
{
	idr_destroy(&entry->parent->idr);
	kfree_rcu(entry->parent, rcu);
}

static inline u32 dev_xtc_entry_total(struct xtc_entry *entry)
{
	const struct bpf_prog_array_item *item;
	const struct bpf_prog *prog;
	u32 num = 0;

	item = &entry->items[0];
	while ((prog = READ_ONCE(item->prog))) {
		num++;
		item++;
	}
	return num;
}

static inline enum tc_action_base xtc_action_code(struct sk_buff *skb, int code)
{
	switch (code) {
	case TC_PASS:
		skb->tc_index = qdisc_skb_cb(skb)->tc_classid;
		fallthrough;
	case TC_DROP:
	case TC_REDIRECT:
		return code;
	case TC_NEXT:
	default:
		return TC_NEXT;
	}
}

int xtc_prog_attach(const union bpf_attr *attr, struct bpf_prog *prog);
int xtc_prog_detach(const union bpf_attr *attr);
int xtc_prog_query(const union bpf_attr *attr,
		   union bpf_attr __user *uattr);
int xtc_link_attach(const union bpf_attr *attr, struct bpf_prog *prog);
void dev_xtc_uninstall(struct net_device *dev);
#else
static inline int xtc_prog_attach(const union bpf_attr *attr,
				  struct bpf_prog *prog)
{
	return -EINVAL;
}

static inline int xtc_prog_detach(const union bpf_attr *attr)
{
	return -EINVAL;
}

static inline int xtc_prog_query(const union bpf_attr *attr,
				 union bpf_attr __user *uattr)
{
	return -EINVAL;
}

static inline int xtc_link_attach(const union bpf_attr *attr,
				  struct bpf_prog *prog)
{
	return -EINVAL;
}

static inline void dev_xtc_uninstall(struct net_device *dev)
{
}
#endif /* CONFIG_NET_XGRESS */
#endif /* __NET_XTC_H */
