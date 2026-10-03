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
 * program lifetime.
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
#include "blk.h"

/* the core calls .init() unconditionally; the struct is found by name already */
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
	 * bdev, q and link are kernel-private and start zeroed; the
	 * struct_ops core rejects a nonzero userspace value for
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

	return ioc_bpf_attach(ops, link);
}

static void bpf_iocost_unreg(void *kdata, struct bpf_link *link)
{
	struct iocost_model_ops *ops = kdata;
	struct request_queue *q;

	/*
	 * ops->q may already have been cleared by the removal ejection;
	 * take a queue reference under RCU before entering the queue,
	 * as the queue may be dying and its memory is only guaranteed
	 * under rcu_read_lock()
	 */
	rcu_read_lock();
	q = READ_ONCE(ops->q);
	if (!q || !blk_get_queue_rcu(q)) {
		rcu_read_unlock();
		return;
	}
	rcu_read_unlock();

	/*
	 * detach only if this link still owns the attachment: after a
	 * device removal the same map may have been attached to a new
	 * device through another link, and closing the old link must
	 * not tear that down.  The link is re-checked under
	 * rq_qos_mutex inside ioc_bpf_detach().
	 */
	ioc_bpf_detach(ops, link);

	blk_put_queue(q);
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
