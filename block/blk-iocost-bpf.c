// SPDX-License-Identifier: GPL-2.0
/*
 * blk-iocost: BPF struct_ops plumbing for pluggable cost models.
 *
 * Copyright (C) 2026 KylinSoft Corporation.
 *
 * Registers the "iocost_model_ops" struct_ops type. Attachment is per-device:
 * the target device is set in the ops from userspace before load, .reg
 * attaches the model to that device, creating the ioc if needed and switching
 * to the model with the queue frozen before rq_qos_mutex, like io.cost.qos
 * writes, and .unreg detaches it; enabling and disabling the controller stays
 * with io.cost.qos. The struct_ops core owns the program lifetime.
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include "blk-iocost.h"
#include <linux/blk-mq.h>
#include <linux/mutex.h>
#include "blk.h"

/*
/*
 * Deliver iocg_init()/iocg_free() to the cgroups already online on the
 * queue: init walks q->blkg_list in reverse so parents receive it first,
 * like blkcg_activate_policy(); free walks it forward like the blkcg
 * policy teardown. The queue is frozen and quiesced; queue_lock
 * serializes against blkg creation and blkcg_mutex against the delayed
 * list removal in blkg destruction; the callbacks are called with
 * ioc->lock held, the same lock the attachment updates take.
 */
static void ioc_bpf_deliver_iocg_callbacks(struct ioc *ioc,
					   const struct iocost_model_ops *ops,
					   bool init)
{
	struct request_queue *q = ioc->rqos.disk->queue;
	struct blkcg_gq *blkg;

	lockdep_assert_held(&q->blkcg_mutex);
	lockdep_assert_held(&q->queue_lock);
	lockdep_assert_held(&ioc->lock);

	if (init) {
		/* parents first, like blkcg_activate_policy() */
		list_for_each_entry_reverse(blkg, &q->blkg_list, q_node) {
			struct ioc_gq *iocg = blkg_to_iocg(blkg);

			/*
			 * A blkg which never went online never reached the
			 * radix tree, so it must not receive an init either;
			 * the attach runs under the same queue_lock as
			 * blkg_create(), so pd->online is stable here. Any
			 * previous attachment had its delivered flags cleared
			 * before it went away, so none can still be set here.
			 */
			if (!iocg || !iocg->pd.online)
				continue;
			if (ops->iocg_init) {
				ops->iocg_init(blkg->blkcg, q);
				iocg->bpf_iocg_inited = true;
			}
		}
	} else {
		list_for_each_entry(blkg, &q->blkg_list, q_node) {
			struct ioc_gq *iocg = blkg_to_iocg(blkg);

			if (!iocg || !iocg->bpf_iocg_inited)
				continue;
			if (ops->iocg_free)
				ops->iocg_free(blkg->blkcg, q);
			iocg->bpf_iocg_inited = false;
		}
	}
}

static int ioc_bpf_attach(struct iocost_model_ops *ops, struct bpf_link *link)
{
	struct block_device *bdev;
	struct request_queue *q;
	struct gendisk *disk;
	struct ioc *ioc;
	unsigned int memflags;
	int ret;

	bdev = blkdev_get_no_open(new_decode_dev(ops->dev), false);
	if (!bdev)
		return -ENODEV;
	q = bdev->bd_queue;
	disk = bdev->bd_disk;

	if (bdev_is_partition(bdev)) {
		blkdev_put_no_open(bdev);
		return -EINVAL;
	}
	if (!queue_is_mq(q)) {
		blkdev_put_no_open(bdev);
		return -EOPNOTSUPP;
	}

	/*
	 * The freeze is taken before rq_qos_mutex like ioc_qos_write() does;
	 * holding the mutex from the disk_live() check through the model
	 * switch keeps the ioc from being freed under us.
	 */
	memflags = blk_mq_freeze_queue(q);

	mutex_lock(&q->rq_qos_mutex);

	if (!disk_live(disk)) {
		mutex_unlock(&q->rq_qos_mutex);
		blk_mq_unfreeze_queue(q, memflags);
		blkdev_put_no_open(bdev);
		return -ENODEV;
	}
	ioc = q_to_ioc(q);
	if (!ioc) {
		ret = blk_iocost_init(disk);
		if (ret) {
			mutex_unlock(&q->rq_qos_mutex);
			blk_mq_unfreeze_queue(q, memflags);
			blkdev_put_no_open(bdev);
			return ret;
		}
		ioc = q_to_ioc(q);
	}

	blk_mq_quiesce_queue(q);

	/*
	 * Scope the mutex so the tail bdev put runs with blkcg_mutex
	 * already released: dropping the last device reference can
	 * reach disk_release() -> blkcg_exit_disk() ->
	 * blkg_destroy_all(), which takes q->blkcg_mutex.
	 */
	{
		guard(mutex)(&q->blkcg_mutex);
		scoped_guard(spinlock_irqsave, &q->queue_lock) {
			spin_lock(&ioc->lock);
			ret = ioc_attached_model_locked(ioc) ? -EBUSY : 0;
			if (!ret) {
				/*
				 * Take the map reference before the attachment
				 * is published: the readers find the ops
				 * through it. get() cannot fail while .reg
				 * runs, as the core holds a map reference
				 * then, but check it anyway; on failure leave
				 * with no attachment set.
				 */
				if (!bpf_struct_ops_get(ops)) {
					ret = -ENODEV;
				} else {
					rcu_assign_pointer(ioc->attached, ops);
					rcu_assign_pointer(ioc->model, ops);
					ioc->bpf_link = link;

					/* pair iocg_init() with the cgroups online */
					ioc_bpf_deliver_iocg_callbacks(ioc, ops,
								       true);
				}
			}
			spin_unlock(&ioc->lock);
		}
	}

	blk_mq_unquiesce_queue(q);
	blk_mq_unfreeze_queue(q, memflags);
	mutex_unlock(&q->rq_qos_mutex);
	blkdev_put_no_open(bdev);
	return ret;
}

/*
 * Detach a model: switch back to the builtin model when the attached model is
 * in use, clear the attachment and deliver iocg_free() to the cgroups which
 * still exist, under the same freeze and quiesce as the attach.
 */
static void ioc_bpf_detach(struct iocost_model_ops *ops, struct bpf_link *link)
{
	struct block_device *bdev;
	struct request_queue *q;
	struct ioc *ioc;
	bool matched;
	unsigned int memflags;

	/*
	 * A failed lookup means the device is gone; the removal ejection will
	 * detach the model and drop the map reference when rq_qos_exit() runs,
	 * so there is nothing to do here.
	 */
	bdev = blkdev_get_no_open(new_decode_dev(ops->dev), false);
	if (!bdev)
		return;
	q = bdev->bd_queue;

	/*
	 * The attachment is checked under rq_qos_mutex first, so an unmatched
	 * detach exits without freezing.
	 */
	mutex_lock(&q->rq_qos_mutex);
	spin_lock_irq(&q->queue_lock);
	ioc = q_to_ioc(q);
	if (ioc) {
		spin_lock(&ioc->lock);
		matched = ioc_attached_model_locked(ioc) == ops &&
			  ioc->bpf_link == link;
		spin_unlock(&ioc->lock);
	} else {
		matched = false;
	}
	spin_unlock_irq(&q->queue_lock);
	mutex_unlock(&q->rq_qos_mutex);
	if (!matched) {
		blkdev_put_no_open(bdev);
		return;
	}

	/* the freeze is taken before rq_qos_mutex like ioc_qos_write() */
	memflags = blk_mq_freeze_queue(q);

	mutex_lock(&q->rq_qos_mutex);

	/*
	 * Re-check under the mutex before quiescing: the freeze itself does
	 * not touch the tag set, and the removal ejection holds rq_qos_mutex
	 * before the driver frees the tag set, so the check passing here means
	 * the tag set is still alive.
	 */
	spin_lock_irq(&q->queue_lock);
	ioc = q_to_ioc(q);
	if (ioc) {
		spin_lock(&ioc->lock);
		matched = ioc_attached_model_locked(ioc) == ops &&
			  ioc->bpf_link == link;
		spin_unlock(&ioc->lock);
	} else {
		matched = false;
	}
	spin_unlock_irq(&q->queue_lock);
	if (!matched) {
		mutex_unlock(&q->rq_qos_mutex);
		blk_mq_unfreeze_queue(q, memflags);
		blkdev_put_no_open(bdev);
		return;
	}

	blk_mq_quiesce_queue(q);

	/*
	 * Scope the mutex so the tail bdev put runs with blkcg_mutex
	 * already released: dropping the last device reference can
	 * reach disk_release() -> blkcg_exit_disk() ->
	 * blkg_destroy_all(), which takes q->blkcg_mutex.
	 */
	{
		guard(mutex)(&q->blkcg_mutex);
		scoped_guard(spinlock_irqsave, &q->queue_lock) {
			spin_lock(&ioc->lock);
			if (ioc_bpf_model_locked(ioc) == ops)
				rcu_assign_pointer(ioc->model, NULL);
			rcu_assign_pointer(ioc->attached, NULL);
			ioc->bpf_link = NULL;

			ioc_bpf_deliver_iocg_callbacks(ioc, ops, false);
			spin_unlock(&ioc->lock);
		}
	}

	blk_mq_unquiesce_queue(q);
	blk_mq_unfreeze_queue(q, memflags);
	mutex_unlock(&q->rq_qos_mutex);

	blkdev_put_no_open(bdev);
	bpf_struct_ops_put(ops);
}

/*
 * Eject the model on device removal. The caller holds rq_qos_mutex and
 * blkcg_deactivate_policy() has already run, so every existing blkg got
 * iocg_free() from ioc_pd_free() and no walk is needed. The ioc is freed right
 * after, so clearing the pointers and dropping the map reference is all that
 * is left to do.
 */
void ioc_bpf_eject(struct ioc *ioc)
{
	const struct iocost_model_ops *ops;
	unsigned long flags;

	spin_lock_irqsave(&ioc->lock, flags);
	ops = ioc_attached_model_locked(ioc);
	if (ops) {
		rcu_assign_pointer(ioc->attached, NULL);
		if (ioc_bpf_model_locked(ioc) == ops)
			rcu_assign_pointer(ioc->model, NULL);
		ioc->bpf_link = NULL;
	}
	spin_unlock_irqrestore(&ioc->lock, flags);

	if (ops)
		bpf_struct_ops_put(ops);
}

/* nothing to look up: the core finds the struct by name before calling */
static int bpf_iocost_model_init(struct btf *btf)
{
	return 0;
}

static bool bpf_iocost_is_valid_access(int off, int size,
				       enum bpf_access_type type,
				       const struct bpf_prog *prog,
				       struct bpf_insn_access_aux *info)
{
	return bpf_tracing_btf_ctx_access(off, size, type, prog, info);
}

/*
 * No iocost-specific helpers; bpf_base_func_proto already covers the
 * cgroup storage helpers under CONFIG_CGROUPS.
 */
static const struct bpf_func_proto *
bpf_iocost_get_func_proto(enum bpf_func_id func_id,
			  const struct bpf_prog *prog)
{
	return bpf_base_func_proto(func_id, prog);
}

static int bpf_iocost_check_member(const struct btf_type *t,
				   const struct btf_member *member,
				   const struct bpf_prog *prog)
{
	/* every callback runs under RCU read lock or a spinlock */
	if (prog->sleepable)
		return -EINVAL;
	return 0;
}

static int bpf_iocost_init_member(const struct btf_type *t,
				  const struct btf_member *member,
				  void *kdata, const void *udata)
{
	struct iocost_model_ops *ops = kdata;
	const struct iocost_model_ops *uops = udata;
	u32 moff = __btf_member_bit_offset(t, member) / 8;

	switch (moff) {
	/*
	 * The struct_ops core rejects a nonzero userspace value for
	 * non-function members this callback does not claim.
	 */
	case offsetof(struct iocost_model_ops, dev):
		ops->dev = uops->dev;
		return 1;
	case offsetof(struct iocost_model_ops, read_vtime_per_page):
		ops->read_vtime_per_page = uops->read_vtime_per_page;
		return 1;
	case offsetof(struct iocost_model_ops, write_vtime_per_page):
		ops->write_vtime_per_page = uops->write_vtime_per_page;
		return 1;
	}

	return 0;
}

/*
 * A complete model prices every charged IO and carries both transfer
 * coefficients; a missing calc_cost would be a NULL call from the
 * submission path and missing coefficients would silently zero the
 * completion-time sizing (see ioc_rqos_done()), so the model is
 * rejected before it can be registered. iocg_init() and iocg_free()
 * must come in pairs too: a model implementing only one of them would
 * build per-cgroup state that nothing ever tears down.
 */
static bool iocost_model_complete(const struct iocost_model_ops *ops)
{
	return ops->calc_cost && ops->read_vtime_per_page &&
	       ops->write_vtime_per_page &&
	       !!ops->iocg_init == !!ops->iocg_free;
}

/*
 * kvalue is zeroed at map allocation and function members are only written
 * when the BPF side provides a prog, so a model which did not implement
 * calc_cost leaves it NULL, and missing coefficients read as zero. This is
 * reached from the map-update path of both map flavors, before the model can
 * be registered.
 */
static int bpf_iocost_validate(void *kdata)
{
	struct iocost_model_ops *ops = kdata;

	/*
	 * Bound the transfer coefficients so that coefficient * pages cannot
	 * wrap u64 for any possible request size.
	 */
	if (ops->read_vtime_per_page > (VTIME_PER_SEC >> IOC_SECT_TO_PAGE_SHIFT) ||
	    ops->write_vtime_per_page > (VTIME_PER_SEC >> IOC_SECT_TO_PAGE_SHIFT))
		return -EINVAL;

	return iocost_model_complete(ops) ? 0 : -EINVAL;
}

static int bpf_iocost_reg(void *kdata, struct bpf_link *link)
{
	struct iocost_model_ops *ops = kdata;

	/* validate() has run by now; only the device is left to check */
	if (!ops->dev)
		return -EINVAL;

	return ioc_bpf_attach(ops, link);
}

static void bpf_iocost_unreg(void *kdata, struct bpf_link *link)
{
	struct iocost_model_ops *ops = kdata;

	/* a gone device is handled inside ioc_bpf_detach() */
	ioc_bpf_detach(ops, link);
}

static const struct bpf_verifier_ops bpf_iocost_verifier_ops = {
	.get_func_proto = bpf_iocost_get_func_proto,
	.is_valid_access = bpf_iocost_is_valid_access,
};

static u64 bpf_iocost_calc_cost_stub(struct bio *bio, u64 flags)
{
	return 0;
}

static void bpf_iocost_iocg_init_stub(struct blkcg *blkcg,
				      struct request_queue *q)
{ }
static void bpf_iocost_iocg_free_stub(struct blkcg *blkcg,
				      struct request_queue *q)
{ }

static struct iocost_model_ops __bpf_ops_iocost_model_ops = {
	.calc_cost = bpf_iocost_calc_cost_stub,
	.iocg_init = bpf_iocost_iocg_init_stub,
	.iocg_free = bpf_iocost_iocg_free_stub,
};

static struct bpf_struct_ops bpf_iocost_model_ops = {
	.verifier_ops = &bpf_iocost_verifier_ops,
	.init = bpf_iocost_model_init,
	.check_member = bpf_iocost_check_member,
	.init_member = bpf_iocost_init_member,
	.validate = bpf_iocost_validate,
	.reg = bpf_iocost_reg,
	.unreg = bpf_iocost_unreg,
	.name = "iocost_model_ops",
	.cfi_stubs = &__bpf_ops_iocost_model_ops,
	.owner = THIS_MODULE,
};

static int __init bpf_iocost_init(void)
{
	return register_bpf_struct_ops(&bpf_iocost_model_ops, iocost_model_ops);
}
late_initcall(bpf_iocost_init);
