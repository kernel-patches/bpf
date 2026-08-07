// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Block I/O Controller-related BPF kfuncs and auxiliary code.
 *
 * These let a BPF program read a cgroup's io.stat counters. A program turns a
 * cgroup's css into a struct blkcg with bpf_get_blkcg(), flushes the stats with
 * bpf_blkcg_flush_stats(), then walks the cgroup's per-device blkgs with the
 * bpf_iter_blkg open-coded iterator, reading each device's counters with
 * bpf_blkg_iostat_bytes()/bpf_blkg_iostat_ios(). It mirrors the memory
 * controller kfuncs in mm/bpf_memcontrol.c, but adds a per-device dimension:
 * unlike memcg, blkcg keeps one blkg (and one io.stat line) per block device.
 *
 * This file lives in block/ because the blkcg/blkg struct layouts are private
 * to block/blk-cgroup.h.
 */

#include "blk-cgroup.h"

#include <linux/bpf.h>
#include <linux/btf_ids.h>
#include <linux/preempt.h>
#include <linux/rculist.h>

__bpf_kfunc_start_defs();

/**
 * bpf_get_root_blkcg - Returns a pointer to the root block cgroup
 *
 * The function has KF_ACQUIRE semantics, even though the root block cgroup is
 * never destroyed and doesn't require reference counting. It's safe to pass it
 * to bpf_put_blkcg().
 *
 * Note that the root cgroup is special: its counters are the disks' own
 * statistics, so they cover every cgroup's I/O rather than only the root's.
 * This matches what the root io.stat file prints.
 *
 * Return: A pointer to the root block cgroup.
 */
__bpf_kfunc struct blkcg *bpf_get_root_blkcg(void)
{
	/* css_get() is not needed */
	return &blkcg_root;
}

/**
 * bpf_get_blkcg - Get a reference to a block cgroup
 * @css: pointer to the css structure
 *
 * It's fine to pass a css which belongs to any cgroup controller,
 * e.g. unified hierarchy's main css.
 *
 * Implements KF_ACQUIRE semantics.
 *
 * Return: A pointer to a blkcg structure after bumping the corresponding css's
 * reference counter, or NULL if the io controller is not enabled on the cgroup.
 */
__bpf_kfunc struct blkcg *bpf_get_blkcg(struct cgroup_subsys_state *css)
{
	struct blkcg *blkcg = NULL;

	if (css->ss == &io_cgrp_subsys)
		return css_tryget(css) ? css_to_blkcg(css) : NULL;

	/*
	 * Some other controller's css, or the cgroup's own one. Look up the io
	 * controller's css; rcu keeps it alive between the load and the tryget.
	 * Acquire and release rcu on one straight path, so that block/'s lock
	 * context analysis can follow it.
	 */
	rcu_read_lock();
	css = rcu_dereference_raw(css->cgroup->subsys[io_cgrp_id]);
	if (css && css_tryget(css))
		blkcg = css_to_blkcg(css);
	rcu_read_unlock();

	return blkcg;
}

/**
 * bpf_put_blkcg - Put a reference to a block cgroup
 * @blkcg: block cgroup to release
 *
 * Releases a previously acquired blkcg reference.
 * Implements KF_RELEASE semantics.
 */
__bpf_kfunc void bpf_put_blkcg(struct blkcg *blkcg)
{
	css_put(&blkcg->css);
}

/**
 * bpf_blkcg_flush_stats - Flush a block cgroup's io statistics
 * @blkcg: block cgroup
 *
 * Call this before reading counters for up-to-date values. Sleepable.
 *
 * It does what reading the io.stat file does, which differs by cgroup. For a
 * non-root cgroup it folds the per-cpu deltas into the per-device aggregates
 * and up the cgroup tree. The root cgroup is not accounted through rstat at
 * all, so for it the per-device aggregates are refilled from the disks'
 * own statistics, which count every cgroup's I/O.
 *
 * The root branch is not self-limiting the way the rstat one is: it rereads
 * every disk on every call, while a second rstat flush finds nothing left to
 * fold. The numbers it produces are the same for every cgroup, so read them
 * once rather than once per cgroup of a walk.
 */
__bpf_kfunc void bpf_blkcg_flush_stats(struct blkcg *blkcg)
{
	if (!blkcg->css.parent)
		blkcg_fill_root_iostats();
	else
		css_rstat_flush(&blkcg->css);
}

struct bpf_iter_blkg {
	__u64 __opaque[2];
} __attribute__((aligned(8)));

struct bpf_iter_blkg_kern {
	struct blkcg *blkcg;
	struct blkcg_gq *pos;
} __attribute__((aligned(8)));

/**
 * bpf_iter_blkg_new - Start iterating a block cgroup's per-device blkgs
 * @it: iterator to initialize
 * @blkcg: block cgroup whose devices to walk
 *
 * Each yielded blkg holds one block device's counters, the same ones behind a
 * per-device line of the io.stat file. Offline blkgs are skipped, as the file
 * skips them. One case differs: the file prints no line for a blkg whose disk
 * is gone, while the walk still yields it, and bpf_blkg_dev() returns 0 for
 * it. Must be used inside an RCU read section.
 *
 * Return: 0 on success.
 */
__bpf_kfunc int bpf_iter_blkg_new(struct bpf_iter_blkg *it, struct blkcg *blkcg)
{
	struct bpf_iter_blkg_kern *kit = (void *)it;

	BUILD_BUG_ON(sizeof(struct bpf_iter_blkg_kern) > sizeof(struct bpf_iter_blkg));
	BUILD_BUG_ON(__alignof__(struct bpf_iter_blkg_kern) !=
		     __alignof__(struct bpf_iter_blkg));

	kit->blkcg = blkcg;
	kit->pos = NULL;
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

	/* Cleared once the walk is done, see below. */
	if (!kit->blkcg)
		return NULL;

	if (!blkg)
		node = rcu_dereference(hlist_first_rcu(&kit->blkcg->blkg_list));
	else
		node = rcu_dereference(hlist_next_rcu(&blkg->blkcg_node));

	/* Skip offline blkgs, matching the io.stat file. */
	while (node) {
		blkg = hlist_entry(node, struct blkcg_gq, blkcg_node);
		if (blkg->online) {
			kit->pos = blkg;
			return blkg;
		}
		node = rcu_dereference(hlist_next_rcu(&blkg->blkcg_node));
	}

	/*
	 * Forget the list head as well. The verifier assumes that an iterator
	 * which returned NULL keeps returning NULL, and stops checking the
	 * loop for termination once it has; starting the walk over would let
	 * such a loop spin forever.
	 */
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

/*
 * Read one counter out of @blkg's flushed io.stat aggregate. @counters is one
 * of the two arrays in blkg->iostat.cur; both are guarded by that struct's
 * seqlock, the one the io.stat file uses. Returns (u64)-1 if the counter
 * cannot be read.
 */
static u64 blkg_iostat_read(struct blkcg_gq *blkg, const u64 *counters,
			    enum blkg_iostat_type rw)
{
	struct blkg_iostat_set *bis = &blkg->iostat;
	unsigned int seq;
	u64 val;

	if ((unsigned int)rw >= BLKG_IOSTAT_NR)
		return (u64)-1;

	/*
	 * On 32-bit the loop below really is a seqcount retry loop. Every
	 * writer of blkg->iostat keeps interrupts off, so only an NMI can land
	 * inside an update, and then the loop would never end. These kfuncs
	 * are reachable from a perf event program, which does run in NMI, so
	 * give up rather than spin. On 64-bit the loop compiles away.
	 */
	if (BITS_PER_LONG == 32 && in_nmi())
		return (u64)-1;

	do {
		seq = u64_stats_fetch_begin(&bis->sync);
		val = counters[rw];
	} while (u64_stats_fetch_retry(&bis->sync, seq));

	return val;
}

/**
 * bpf_blkg_iostat_bytes - Read a device's io.stat byte counter
 * @blkg: block group (one device of a block cgroup)
 * @rw: which counter (BLKG_IOSTAT_READ / _WRITE / _DISCARD)
 *
 * Reads the flushed aggregate, so call bpf_blkcg_flush_stats() first for
 * up-to-date values. The read uses the u64_stats seqlock, like the io.stat
 * file.
 *
 * Return: the number of bytes, or (u64)-1 if @rw is out of range or the
 * counter cannot be read.
 */
__bpf_kfunc u64 bpf_blkg_iostat_bytes(struct blkcg_gq *blkg,
				      enum blkg_iostat_type rw)
{
	return blkg_iostat_read(blkg, blkg->iostat.cur.bytes, rw);
}

/**
 * bpf_blkg_iostat_ios - Read a device's io.stat I/O count
 * @blkg: block group (one device of a block cgroup)
 * @rw: which counter (BLKG_IOSTAT_READ / _WRITE / _DISCARD)
 *
 * Return: the number of I/Os, or (u64)-1 if @rw is out of range or the
 * counter cannot be read.
 */
__bpf_kfunc u64 bpf_blkg_iostat_ios(struct blkcg_gq *blkg,
				    enum blkg_iostat_type rw)
{
	return blkg_iostat_read(blkg, blkg->iostat.cur.ios, rw);
}

/**
 * bpf_blkg_dev - Return a blkg's device id
 * @blkg: block group
 *
 * Return: the device's dev_t (use MAJOR()/MINOR() to split), or 0 if the blkg
 * has no disk.
 */
__bpf_kfunc u64 bpf_blkg_dev(struct blkcg_gq *blkg)
{
	if (!blkg->q || !blkg->q->disk)
		return 0;

	return blkg->q->disk->part0->bd_dev;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_blkcg_kfuncs)
BTF_ID_FLAGS(func, bpf_get_root_blkcg, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_get_blkcg, KF_ACQUIRE | KF_RET_NULL | KF_RCU)
BTF_ID_FLAGS(func, bpf_put_blkcg, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_blkcg_flush_stats, KF_SLEEPABLE)

BTF_ID_FLAGS(func, bpf_iter_blkg_new, KF_ITER_NEW | KF_RCU_PROTECTED)
BTF_ID_FLAGS(func, bpf_iter_blkg_next, KF_ITER_NEXT | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_iter_blkg_destroy, KF_ITER_DESTROY)

BTF_ID_FLAGS(func, bpf_blkg_iostat_bytes, KF_RCU)
BTF_ID_FLAGS(func, bpf_blkg_iostat_ios, KF_RCU)
BTF_ID_FLAGS(func, bpf_blkg_dev, KF_RCU)
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
