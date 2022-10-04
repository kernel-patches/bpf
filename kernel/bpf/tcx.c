// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Isovalent */

#include <linux/bpf.h>
#include <linux/bpf_mprog.h>
#include <linux/netdevice.h>

#include <net/tcx.h>

int tcx_prog_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
	bool created, ingress = attr->attach_type == BPF_TCX_INGRESS;
	struct net *net = current->nsproxy->net_ns;
	struct bpf_mprog_entry *entry;
	struct net_device *dev;
	int ret;

	rtnl_lock();
	dev = __dev_get_by_index(net, attr->target_ifindex);
	if (!dev) {
		ret = -ENODEV;
		goto out;
	}
	entry = dev_tcx_entry_fetch_or_create(dev, ingress, &created);
	if (!entry) {
		ret = -ENOMEM;
		goto out;
	}
	ret = bpf_mprog_attach(entry, prog, NULL, attr->attach_flags,
			       attr->relative_fd, attr->expected_revision);
	if (ret >= 0) {
		if (ret == BPF_MPROG_SWAP)
			tcx_entry_update(dev, bpf_mprog_peer(entry), ingress);
		bpf_mprog_commit(entry);
		tcx_skeys_inc(ingress);
		ret = 0;
	} else if (created) {
		bpf_mprog_free(entry);
	}
out:
	rtnl_unlock();
	return ret;
}

static bool tcx_release_entry(struct bpf_mprog_entry *entry, int code)
{
	return code == BPF_MPROG_FREE && !tcx_entry(entry)->miniq;
}

int tcx_prog_detach(const union bpf_attr *attr, struct bpf_prog *prog)
{
	bool tcx_release, ingress = attr->attach_type == BPF_TCX_INGRESS;
	struct net *net = current->nsproxy->net_ns;
	struct bpf_mprog_entry *entry, *peer;
	struct net_device *dev;
	int ret;

	rtnl_lock();
	dev = __dev_get_by_index(net, attr->target_ifindex);
	if (!dev) {
		ret = -ENODEV;
		goto out;
	}
	entry = dev_tcx_entry_fetch(dev, ingress);
	if (!entry) {
		ret = -ENOENT;
		goto out;
	}
	ret = bpf_mprog_detach(entry, prog, NULL, attr->attach_flags,
			       attr->relative_fd, attr->expected_revision);
	if (ret >= 0) {
		tcx_release = tcx_release_entry(entry, ret);
		peer = tcx_release ? NULL : bpf_mprog_peer(entry);
		if (ret == BPF_MPROG_SWAP || ret == BPF_MPROG_FREE)
			tcx_entry_update(dev, peer, ingress);
		bpf_mprog_commit(entry);
		tcx_skeys_dec(ingress);
		if (tcx_release)
			bpf_mprog_free(entry);
		ret = 0;
	}
out:
	rtnl_unlock();
	return ret;
}

static void tcx_uninstall(struct net_device *dev, bool ingress)
{
	struct bpf_tuple tuple = {};
	struct bpf_mprog_entry *entry;
	struct bpf_mprog_fp *fp;
	struct bpf_mprog_cp *cp;

	entry = dev_tcx_entry_fetch(dev, ingress);
	if (!entry)
		return;
	tcx_entry_update(dev, NULL, ingress);
	bpf_mprog_commit(entry);
	bpf_mprog_foreach_tuple(entry, fp, cp, tuple) {
		if (tuple.link)
			tcx_link(tuple.link)->dev = NULL;
		else
			bpf_prog_put(tuple.prog);
		tcx_skeys_dec(ingress);
	}
	WARN_ON_ONCE(tcx_entry(entry)->miniq);
	bpf_mprog_free(entry);
}

void dev_tcx_uninstall(struct net_device *dev)
{
	ASSERT_RTNL();
	tcx_uninstall(dev, true);
	tcx_uninstall(dev, false);
}

int tcx_prog_query(const union bpf_attr *attr, union bpf_attr __user *uattr)
{
	bool ingress = attr->query.attach_type == BPF_TCX_INGRESS;
	struct net *net = current->nsproxy->net_ns;
	struct bpf_mprog_entry *entry;
	struct net_device *dev;
	int ret;

	rtnl_lock();
	dev = __dev_get_by_index(net, attr->query.target_ifindex);
	if (!dev) {
		ret = -ENODEV;
		goto out;
	}
	entry = dev_tcx_entry_fetch(dev, ingress);
	if (!entry) {
		ret = -ENOENT;
		goto out;
	}
	ret = bpf_mprog_query(attr, uattr, entry);
out:
	rtnl_unlock();
	return ret;
}

static int tcx_link_prog_attach(struct bpf_link *l, u32 flags, u32 object,
				u32 expected_revision)
{
	struct tcx_link *link = tcx_link(l);
	bool created, ingress = link->location == BPF_TCX_INGRESS;
	struct net_device *dev = link->dev;
	struct bpf_mprog_entry *entry;
	int ret;

	ASSERT_RTNL();
	entry = dev_tcx_entry_fetch_or_create(dev, ingress, &created);
	if (!entry)
		return -ENOMEM;
	ret = bpf_mprog_attach(entry, l->prog, l, flags, object,
			       expected_revision);
	if (ret >= 0) {
		if (ret == BPF_MPROG_SWAP)
			tcx_entry_update(dev, bpf_mprog_peer(entry), ingress);
		bpf_mprog_commit(entry);
		tcx_skeys_inc(ingress);
		ret = 0;
	} else if (created) {
		bpf_mprog_free(entry);
	}
	return ret;
}

static void tcx_link_release(struct bpf_link *l)
{
	struct tcx_link *link = tcx_link(l);
	bool tcx_release, ingress = link->location == BPF_TCX_INGRESS;
	struct bpf_mprog_entry *entry, *peer;
	struct net_device *dev;
	int ret = 0;

	rtnl_lock();
	dev = link->dev;
	if (!dev)
		goto out;
	entry = dev_tcx_entry_fetch(dev, ingress);
	if (!entry) {
		ret = -ENOENT;
		goto out;
	}
	ret = bpf_mprog_detach(entry, l->prog, l, link->flags, 0, 0);
	if (ret >= 0) {
		tcx_release = tcx_release_entry(entry, ret);
		peer = tcx_release ? NULL : bpf_mprog_peer(entry);
		if (ret == BPF_MPROG_SWAP || ret == BPF_MPROG_FREE)
			tcx_entry_update(dev, peer, ingress);
		bpf_mprog_commit(entry);
		tcx_skeys_dec(ingress);
		if (tcx_release)
			bpf_mprog_free(entry);
		link->dev = NULL;
		ret = 0;
	}
out:
	WARN_ON_ONCE(ret);
	rtnl_unlock();
}

static int tcx_link_update(struct bpf_link *l, struct bpf_prog *nprog,
			   struct bpf_prog *oprog)
{
	struct tcx_link *link = tcx_link(l);
	bool ingress = link->location == BPF_TCX_INGRESS;
	struct net_device *dev = link->dev;
	struct bpf_mprog_entry *entry;
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
	entry = dev_tcx_entry_fetch(dev, ingress);
	if (!entry) {
		ret = -ENOENT;
		goto out;
	}
	ret = bpf_mprog_attach(entry, nprog, l,
			       BPF_F_REPLACE | BPF_F_ID | link->flags,
			       l->prog->aux->id, 0);
	if (ret >= 0) {
		if (ret == BPF_MPROG_SWAP)
			tcx_entry_update(dev, bpf_mprog_peer(entry), ingress);
		bpf_mprog_commit(entry);
		tcx_skeys_inc(ingress);
		oprog = xchg(&l->prog, nprog);
		bpf_prog_put(oprog);
		ret = 0;
	}
out:
	rtnl_unlock();
	return ret;
}

static void tcx_link_dealloc(struct bpf_link *l)
{
	kfree(tcx_link(l));
}

static void tcx_link_fdinfo(const struct bpf_link *l, struct seq_file *seq)
{
	const struct tcx_link *link = tcx_link_const(l);
	u32 ifindex = 0;

	rtnl_lock();
	if (link->dev)
		ifindex = link->dev->ifindex;
	rtnl_unlock();

	seq_printf(seq, "ifindex:\t%u\n", ifindex);
	seq_printf(seq, "attach_type:\t%u (%s)\n",
		   link->location,
		   link->location == BPF_TCX_INGRESS ? "ingress" : "egress");
	seq_printf(seq, "flags:\t%u\n", link->flags);
}

static int tcx_link_fill_info(const struct bpf_link *l,
			      struct bpf_link_info *info)
{
	const struct tcx_link *link = tcx_link_const(l);
	u32 ifindex = 0;

	rtnl_lock();
	if (link->dev)
		ifindex = link->dev->ifindex;
	rtnl_unlock();

	info->tcx.ifindex = ifindex;
	info->tcx.attach_type = link->location;
	info->tcx.flags = link->flags;
	return 0;
}

static int tcx_link_detach(struct bpf_link *l)
{
	tcx_link_release(l);
	return 0;
}

static const struct bpf_link_ops tcx_link_lops = {
	.release	= tcx_link_release,
	.detach		= tcx_link_detach,
	.dealloc	= tcx_link_dealloc,
	.update_prog	= tcx_link_update,
	.show_fdinfo	= tcx_link_fdinfo,
	.fill_link_info	= tcx_link_fill_info,
};

int tcx_link_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
	struct net *net = current->nsproxy->net_ns;
	struct bpf_link_primer link_primer;
	struct net_device *dev;
	struct tcx_link *link;
	int fd, err;

	dev = dev_get_by_index(net, attr->link_create.target_ifindex);
	if (!dev)
		return -EINVAL;
	link = kzalloc(sizeof(*link), GFP_USER);
	if (!link) {
		err = -ENOMEM;
		goto out_put;
	}

	bpf_link_init(&link->link, BPF_LINK_TYPE_TCX, &tcx_link_lops, prog);
	link->location = attr->link_create.attach_type;
	link->flags = attr->link_create.flags & (BPF_F_FIRST | BPF_F_LAST);
	link->dev = dev;

	err = bpf_link_prime(&link->link, &link_primer);
	if (err) {
		kfree(link);
		goto out_put;
	}
	rtnl_lock();
	err = tcx_link_prog_attach(&link->link, attr->link_create.flags,
				   attr->link_create.tcx.relative_fd,
				   attr->link_create.tcx.expected_revision);
	if (!err)
		fd = bpf_link_settle(&link_primer);
	rtnl_unlock();
	if (err) {
		link->dev = NULL;
		bpf_link_cleanup(&link_primer);
		goto out_put;
	}
	dev_put(dev);
	return fd;
out_put:
	dev_put(dev);
	return err;
}
