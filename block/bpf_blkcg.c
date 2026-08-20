// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Block I/O Controller-related BPF kfuncs and auxiliary code
 */

#include "blk-cgroup.h"

#include <linux/bpf.h>
#include <linux/btf_ids.h>
#include <linux/rculist.h>

__bpf_kfunc_start_defs();

/**
 * bpf_css_to_blkcg - Cast an io controller css to its block cgroup
 * @css: io controller css
 *
 * Must be called under RCU.
 *
 * Return: The block cgroup, or NULL if @css belongs to another controller.
 */
__bpf_kfunc struct blkcg *
bpf_css_to_blkcg(struct cgroup_subsys_state *css)
{
	if (unlikely(css->ss != &io_cgrp_subsys))
		return NULL;

	return css_to_blkcg(css);
}

struct bpf_iter_blkg {
	__u64 __opaque[2];
} __aligned(8);

struct bpf_iter_blkg_kern {
	struct blkcg *blkcg;
	struct blkcg_gq *pos;
} __aligned(8);

/**
 * bpf_iter_blkg_new - Start iterating a block cgroup's per-device blkgs
 * @it: iterator to initialize
 * @blkcg: block cgroup to iterate
 *
 * Each blkg holds one device's io.stat counters. Offline blkgs are skipped.
 * A blkg without a disk can be returned. Root blkgs do not contain the
 * system-wide statistics shown by root io.stat. Must run under RCU.
 *
 * Return: 0 on success.
 */
__bpf_kfunc int bpf_iter_blkg_new(struct bpf_iter_blkg *it,
				  struct blkcg *blkcg)
{
	struct bpf_iter_blkg_kern *kit = (void *)it;

	BUILD_BUG_ON(sizeof(struct bpf_iter_blkg_kern) > sizeof(struct bpf_iter_blkg));
	BUILD_BUG_ON(__alignof__(struct bpf_iter_blkg_kern) !=
		     __alignof__(struct bpf_iter_blkg));

	kit->pos = NULL;
	kit->blkcg = blkcg;
	return 0;
}

/**
 * bpf_iter_blkg_next - Return the next online blkg of the iterated block cgroup
 * @it: iterator
 *
 * Return: the next online blkg, or NULL when the walk is done.
 */
__bpf_kfunc struct blkcg_gq *bpf_iter_blkg_next(struct bpf_iter_blkg *it)
{
	struct bpf_iter_blkg_kern *kit = (void *)it;
	struct blkcg_gq *blkg = kit->pos;
	struct hlist_node *node;

	if (!kit->blkcg)
		return NULL;

	if (!blkg)
		node = rcu_dereference(hlist_first_rcu(&kit->blkcg->blkg_list));
	else
		node = rcu_dereference(hlist_next_rcu(&blkg->blkcg_node));

	/* Skip offline blkgs, matching io.stat. */
	while (node) {
		blkg = hlist_entry(node, struct blkcg_gq, blkcg_node);
		/* A race only changes whether this blkg is returned. */
		if (data_race(blkg->online)) {
			kit->pos = blkg;
			return blkg;
		}
		node = rcu_dereference(hlist_next_rcu(&blkg->blkcg_node));
	}

	/* The iterator must keep returning NULL after completion. */
	kit->pos = NULL;
	kit->blkcg = NULL;
	return NULL;
}

/**
 * bpf_iter_blkg_destroy - Tear down a blkg iterator
 * @it: iterator
 */
__bpf_kfunc void bpf_iter_blkg_destroy(struct bpf_iter_blkg *it)
{
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_blkcg_kfuncs)
BTF_ID_FLAGS(func, bpf_css_to_blkcg,
	     KF_RCU | KF_RCU_PROTECTED | KF_RET_NULL)

BTF_ID_FLAGS(func, bpf_iter_blkg_new,
	     KF_ITER_NEW | KF_RCU | KF_RCU_PROTECTED)
BTF_ID_FLAGS(func, bpf_iter_blkg_next, KF_ITER_NEXT | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_iter_blkg_destroy, KF_ITER_DESTROY)
BTF_KFUNCS_END(bpf_blkcg_kfuncs)

static const struct btf_kfunc_id_set bpf_blkcg_kfunc_set = {
	.owner		= THIS_MODULE,
	.set		= &bpf_blkcg_kfuncs,
};

static int __init bpf_blkcg_init(void)
{
	int err;

	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC,
					&bpf_blkcg_kfunc_set);
	if (err)
		pr_warn("error while registering bpf blkcg kfuncs: %d\n", err);

	return err;
}
late_initcall(bpf_blkcg_init);
