// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2022 Isovalent */

#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/netdevice.h>

#include <net/xtc.h>

static int __xtc_prog_attach(struct net_device *dev, bool ingress, u32 limit,
			     u32 id, struct bpf_prog *nprog, u32 prio, u32 flags)
{
	struct bpf_prog_array_item *item, *tmp;
	struct xtc_entry *entry, *peer;
	struct bpf_prog *oprog;
	bool created;
	int i, j;

	ASSERT_RTNL();

	entry = dev_xtc_entry_fetch(dev, ingress, &created);
	if (!entry)
		return -ENOMEM;
	for (i = 0; i < limit; i++) {
		item = &entry->items[i];
		oprog = item->prog;
		if (!oprog)
			break;
		if (item->bpf_priority == prio) {
			if (item->bpf_id == id &&
			    (flags & BPF_F_REPLACE)) {
				/* Pairs with READ_ONCE() in xtc_run_progs(). */
				WRITE_ONCE(item->prog, nprog);
				item->bpf_id = id;
				if (!id)
					bpf_prog_put(oprog);
				dev_xtc_entry_prio_set(entry, prio, nprog);
				return prio;
			}
			return -EBUSY;
		}
	}
	if (dev_xtc_entry_total(entry) >= limit)
		return -ENOSPC;
	prio = dev_xtc_entry_prio_new(entry, prio, nprog);
	if (prio < 0) {
		if (created)
			dev_xtc_entry_free(entry);
		return -ENOMEM;
	}
	peer = dev_xtc_entry_peer(entry);
	dev_xtc_entry_clear(peer);
	for (i = 0, j = 0; i < limit; i++, j++) {
		item = &entry->items[i];
		tmp = &peer->items[j];
		oprog = item->prog;
		if (!oprog) {
			if (i == j) {
				tmp->prog = nprog;
				tmp->bpf_priority = prio;
				tmp->bpf_id = id;
			}
			break;
		} else if (item->bpf_priority < prio) {
			tmp->prog = oprog;
			tmp->bpf_priority = item->bpf_priority;
			tmp->bpf_id = item->bpf_id;
		} else if (item->bpf_priority > prio) {
			if (i == j) {
				tmp->prog = nprog;
				tmp->bpf_priority = prio;
				tmp->bpf_id = id;
				tmp = &peer->items[++j];
			}
			tmp->prog = oprog;
			tmp->bpf_priority = item->bpf_priority;
			tmp->bpf_id = item->bpf_id;
		}
	}
	dev_xtc_entry_update(dev, peer, ingress);
	if (ingress)
		net_inc_ingress_queue();
	else
		net_inc_egress_queue();
	xtc_inc();
	return prio;
}

int xtc_prog_attach(const union bpf_attr *attr, struct bpf_prog *nprog)
{
	struct net *net = current->nsproxy->net_ns;
	bool ingress = attr->attach_type == BPF_NET_INGRESS;
	struct net_device *dev;
	int ret;

	if (attr->attach_flags & ~BPF_F_REPLACE)
		return -EINVAL;
	rtnl_lock();
	dev = __dev_get_by_index(net, attr->target_ifindex);
	if (!dev) {
		rtnl_unlock();
		return -EINVAL;
	}
	ret = __xtc_prog_attach(dev, ingress, XTC_MAX_ENTRIES, 0, nprog,
				attr->attach_priority, attr->attach_flags);
	rtnl_unlock();
	return ret;
}

static int __xtc_prog_detach(struct net_device *dev, bool ingress, u32 limit,
			     u32 id, u32 prio)
{
	struct bpf_prog_array_item *item, *tmp;
	struct bpf_prog *oprog, *fprog = NULL;
	struct xtc_entry *entry, *peer;
	int i, j;

	ASSERT_RTNL();

	entry = ingress ?
		rcu_dereference_rtnl(dev->xtc_ingress) :
		rcu_dereference_rtnl(dev->xtc_egress);
	if (!entry)
		return -ENOENT;
	peer = dev_xtc_entry_peer(entry);
	dev_xtc_entry_clear(peer);
	for (i = 0, j = 0; i < limit; i++) {
		item = &entry->items[i];
		tmp = &peer->items[j];
		oprog = item->prog;
		if (!oprog)
			break;
		if (item->bpf_priority != prio) {
			tmp->prog = oprog;
			tmp->bpf_priority = item->bpf_priority;
			tmp->bpf_id = item->bpf_id;
			j++;
		} else {
			if (item->bpf_id != id)
				return -EBUSY;
			fprog = oprog;
		}
	}
	if (fprog) {
		dev_xtc_entry_prio_del(peer, prio);
		if (dev_xtc_entry_total(peer) == 0 && !entry->parent->miniq)
			peer = NULL;
		dev_xtc_entry_update(dev, peer, ingress);
		if (!id)
			bpf_prog_put(fprog);
		if (!peer)
			dev_xtc_entry_free(entry);
		if (ingress)
			net_dec_ingress_queue();
		else
			net_dec_egress_queue();
		xtc_dec();
		return 0;
	}
	return -ENOENT;
}

int xtc_prog_detach(const union bpf_attr *attr)
{
	struct net *net = current->nsproxy->net_ns;
	bool ingress = attr->attach_type == BPF_NET_INGRESS;
	struct net_device *dev;
	int ret;

	if (attr->attach_flags || !attr->attach_priority)
		return -EINVAL;
	rtnl_lock();
	dev = __dev_get_by_index(net, attr->target_ifindex);
	if (!dev) {
		rtnl_unlock();
		return -EINVAL;
	}
	ret = __xtc_prog_detach(dev, ingress, XTC_MAX_ENTRIES, 0,
				attr->attach_priority);
	rtnl_unlock();
	return ret;
}

static void __xtc_prog_detach_all(struct net_device *dev, bool ingress, u32 limit)
{
	struct bpf_prog_array_item *item;
	struct xtc_entry *entry;
	struct bpf_prog *prog;
	int i;

	ASSERT_RTNL();

	entry = ingress ?
		rcu_dereference_rtnl(dev->xtc_ingress) :
		rcu_dereference_rtnl(dev->xtc_egress);
	if (!entry)
		return;
	dev_xtc_entry_update(dev, NULL, ingress);
	for (i = 0; i < limit; i++) {
		item = &entry->items[i];
		prog = item->prog;
		if (!prog)
			break;
		dev_xtc_entry_prio_del(entry, item->bpf_priority);
		if (!item->bpf_id)
			bpf_prog_put(prog);
		if (ingress)
			net_dec_ingress_queue();
		else
			net_dec_egress_queue();
		xtc_dec();
	}
	dev_xtc_entry_free(entry);
}

void dev_xtc_uninstall(struct net_device *dev)
{
	__xtc_prog_detach_all(dev, true,  XTC_MAX_ENTRIES + 1);
	__xtc_prog_detach_all(dev, false, XTC_MAX_ENTRIES + 1);
}

static int
__xtc_prog_query(const union bpf_attr *attr, union bpf_attr __user *uattr,
		 struct net_device *dev, bool ingress, u32 limit)
{
	struct bpf_query_info info, __user *uinfo;
	struct bpf_prog_array_item *item;
	struct xtc_entry *entry;
	struct bpf_prog *prog;
	u32 i, flags = 0, cnt;
	int ret = 0;

	ASSERT_RTNL();

	entry = ingress ?
		rcu_dereference_rtnl(dev->xtc_ingress) :
		rcu_dereference_rtnl(dev->xtc_egress);
	if (!entry)
		return -ENOENT;
	cnt = dev_xtc_entry_total(entry);
	if (copy_to_user(&uattr->query.attach_flags, &flags, sizeof(flags)))
		return -EFAULT;
	if (copy_to_user(&uattr->query.prog_cnt, &cnt, sizeof(cnt)))
		return -EFAULT;
	uinfo = u64_to_user_ptr(attr->query.prog_ids);
	if (attr->query.prog_cnt == 0 || !uinfo || !cnt)
		/* return early if user requested only program count + flags */
		return 0;
	if (attr->query.prog_cnt < cnt) {
		cnt = attr->query.prog_cnt;
		ret = -ENOSPC;
	}
	for (i = 0; i < limit; i++) {
		item = &entry->items[i];
		prog = item->prog;
		if (!prog)
			break;
		info.prog_id = prog->aux->id;
		info.link_id = item->bpf_id;
		info.prio = item->bpf_priority;
		if (copy_to_user(uinfo + i, &info, sizeof(info)))
			return -EFAULT;
		if (i + 1 == cnt)
			break;
	}
	return ret;
}

int xtc_prog_query(const union bpf_attr *attr, union bpf_attr __user *uattr)
{
	struct net *net = current->nsproxy->net_ns;
	bool ingress = attr->query.attach_type == BPF_NET_INGRESS;
	struct net_device *dev;
	int ret;

	if (attr->query.query_flags || attr->query.attach_flags)
		return -EINVAL;
	rtnl_lock();
	dev = __dev_get_by_index(net, attr->query.target_ifindex);
	if (!dev) {
		rtnl_unlock();
		return -EINVAL;
	}
	ret = __xtc_prog_query(attr, uattr, dev, ingress, XTC_MAX_ENTRIES);
	rtnl_unlock();
	return ret;
}

static int __xtc_link_attach(struct bpf_link *l, u32 id)
{
	struct bpf_tc_link *link = container_of(l, struct bpf_tc_link, link);
	int ret;

	rtnl_lock();
	ret = __xtc_prog_attach(link->dev, link->location == BPF_NET_INGRESS,
				XTC_MAX_ENTRIES, id, l->prog, link->priority,
				0);
	if (ret > 0) {
		link->priority = ret;
		ret = 0;
	}
	rtnl_unlock();
	return ret;
}

static int xtc_link_update(struct bpf_link *l, struct bpf_prog *nprog,
			   struct bpf_prog *oprog)
{
	struct bpf_tc_link *link = container_of(l, struct bpf_tc_link, link);
	int ret = 0;

	rtnl_lock();
	if (!link->dev) {
		ret = -ENOLINK;
		goto out;
	}
	if (oprog && l->prog != oprog) {
		ret = -EPERM;
		goto out;
	}
	oprog = l->prog;
	if (oprog == nprog) {
		bpf_prog_put(nprog);
		goto out;
	}
	ret = __xtc_prog_attach(link->dev, link->location == BPF_NET_INGRESS,
				XTC_MAX_ENTRIES, l->id, nprog, link->priority,
				BPF_F_REPLACE);
	if (ret == link->priority) {
		oprog = xchg(&l->prog, nprog);
		bpf_prog_put(oprog);
		ret = 0;
	}
out:
	rtnl_unlock();
	return ret;
}

static void xtc_link_release(struct bpf_link *l)
{
	struct bpf_tc_link *link = container_of(l, struct bpf_tc_link, link);

	rtnl_lock();
	if (link->dev) {
		WARN_ON(__xtc_prog_detach(link->dev,
					  link->location == BPF_NET_INGRESS,
					  XTC_MAX_ENTRIES, l->id, link->priority));
		link->dev = NULL;
	}
	rtnl_unlock();
}

static void xtc_link_dealloc(struct bpf_link *l)
{
	struct bpf_tc_link *link = container_of(l, struct bpf_tc_link, link);

	kfree(link);
}

static const struct bpf_link_ops bpf_tc_link_lops = {
	.release	= xtc_link_release,
	.dealloc	= xtc_link_dealloc,
	.update_prog	= xtc_link_update,
};

int xtc_link_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
	struct net *net = current->nsproxy->net_ns;
	struct bpf_link_primer link_primer;
	struct bpf_tc_link *link;
	struct net_device *dev;
	int fd, err;

	if (attr->link_create.flags)
		return -EINVAL;
	dev = dev_get_by_index(net, attr->link_create.target_ifindex);
	if (!dev)
		return -EINVAL;
	link = kzalloc(sizeof(*link), GFP_USER);
	if (!link) {
		err = -ENOMEM;
		goto out_put;
	}

	bpf_link_init(&link->link, BPF_LINK_TYPE_TC, &bpf_tc_link_lops, prog);
	link->priority = attr->link_create.tc.priority;
	link->location = attr->link_create.attach_type;
	link->dev = dev;

	err = bpf_link_prime(&link->link, &link_primer);
	if (err) {
		kfree(link);
		goto out_put;
	}
	err = __xtc_link_attach(&link->link, link_primer.id);
	if (err) {
		link->dev = NULL;
		bpf_link_cleanup(&link_primer);
		goto out_put;
	}

	fd = bpf_link_settle(&link_primer);
	dev_put(dev);
	return fd;
out_put:
	dev_put(dev);
	return err;
}
