// SPDX-License-Identifier: GPL-2.0
/*
 * blk-iocost: BPF struct_ops plumbing for pluggable cost models.
 *
 * Registers the "iocost_model_ops" struct_ops type.  Attachment is
 * per-device and follows the hid_bpf_ops model: the target device is
 * set in the ops from userspace before load, .reg attaches the model
 * to that device, creating the ioc if needed and switching to the
 * model under the same queue freeze and quiesce as io.cost.model
 * writes, and .unreg detaches it; enabling and disabling the
 * controller stays with io.cost.qos.  The struct_ops core owns the
 * program lifetime.  There is no name registry and no separate
 * bound-state bookkeeping.
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/blk-iocost.h>
#include <linux/blk-mq.h>
#include <linux/mutex.h>

struct block_device *blkdev_get_no_open(dev_t dev, bool autoload);
void blkdev_put_no_open(struct block_device *bdev);
bool blk_get_queue_rcu(struct request_queue *q);
void blk_put_queue(struct request_queue *q);

static int bpf_iocost_model_init(struct btf *btf)
{
	s32 type_id;

	type_id = btf_find_by_name_kind(btf, "iocost_model_ops", BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
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
	/* calc_cost() is called with RCU read lock held */
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
	case offsetof(struct iocost_model_ops, bdev):
		/*
		 * kernel-private: the bdev reference held while
		 * attached; reject a userspace value
		 */
		if (uops->bdev)
			return -EINVAL;
		ops->bdev = NULL;
		return 1;
	case offsetof(struct iocost_model_ops, q):
		/* kernel-private: the queue of the attached device */
		if (uops->q)
			return -EINVAL;
		ops->q = NULL;
		return 1;
	case offsetof(struct iocost_model_ops, dev):
		/*
		 * copy it and return 1 to indicate that the member is
		 * handled here, or the verifier rejects the map if the
		 * userspace value is nonzero
		 */
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
 * kvalue is zeroed at map allocation and function members are only
 * written when the BPF side provides a prog, so a model which did
 * not implement calc_cost leaves it NULL.  The dispatch would call
 * it on every bio, so reject it here.
 */
static int bpf_iocost_validate(void *kdata)
{
	struct iocost_model_ops *ops = kdata;

	return ops->calc_cost ? 0 : -EINVAL;
}

static int bpf_iocost_reg(void *kdata, struct bpf_link *link)
{
	struct iocost_model_ops *ops = kdata;

	if (!ops->dev)
		return -EINVAL;

	return ioc_bpf_attach(ops);
}

static void bpf_iocost_unreg(void *kdata, struct bpf_link *link)
{
	struct iocost_model_ops *ops = kdata;
	struct block_device *bdev;
	struct request_queue *q;

	/*
	 * ops->q may already have been cleared by the removal ejection;
	 * take a queue reference under RCU before entering the queue,
	 * as the queue may be dying and its memory is only guaranteed
	 * under rcu_read_lock()
	 */
	rcu_read_lock();
	q = rcu_dereference(ops->q);
	if (!q || !blk_get_queue_rcu(q)) {
		rcu_read_unlock();
		return;
	}
	rcu_read_unlock();

	/*
	 * take rq_qos_mutex before touching the queue further: the
	 * removal ejection clears ops->q under it, inside rq_qos_exit()
	 * and before blk_mq_exit_queue() releases the hardware queues,
	 * so holding it and seeing a non-NULL ops->q guarantees the
	 * queue is still safe to freeze.  The freeze and quiesce are
	 * done inside ioc_bpf_detach(), under the mutex.
	 */
	mutex_lock(&q->rq_qos_mutex);
	if (!ops->q) {
		/* the removal ejection won the race; nothing to detach */
		mutex_unlock(&q->rq_qos_mutex);
		blk_put_queue(q);
		return;
	}
	bdev = ops->bdev;
	ioc_bpf_detach(ops);
	mutex_unlock(&q->rq_qos_mutex);
	blk_put_queue(q);

	/* drop the attach reference when we did the detach */
	if (bdev)
		blkdev_put_no_open(bdev);
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
