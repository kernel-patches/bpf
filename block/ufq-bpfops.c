// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 KylinSoft Corporation.
 * Copyright (c) 2026 Kaitao Cheng <chengkaitao@kylinos.cn>
 */
#include <linux/init.h>
#include <linux/types.h>
#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/string.h>
#include <linux/wait.h>
#include <linux/rcupdate.h>
#include "ufq-iosched.h"

struct ufq_iosched_ops ufq_ops;
static atomic_t ufq_bpfops_enabled;
static atomic_t ufq_bpfops_users;
static DECLARE_WAIT_QUEUE_HEAD(ufq_bpfops_wq);

const struct ufq_iosched_ops *ufq_bpfops_tryget(void)
{
	if (!atomic_read(&ufq_bpfops_enabled))
		return NULL;

	atomic_inc(&ufq_bpfops_users);
	/*
	 * Pairs with disable path flipping ufq_bpfops_enabled to make sure no
	 * callback runs after teardown starts.
	 */
	smp_mb__after_atomic();

	if (unlikely(!atomic_read(&ufq_bpfops_enabled))) {
		if (atomic_dec_and_test(&ufq_bpfops_users))
			wake_up_all(&ufq_bpfops_wq);
		return NULL;
	}

	return &ufq_ops;
}

void ufq_bpfops_put(void)
{
	if (atomic_dec_and_test(&ufq_bpfops_users))
		wake_up_all(&ufq_bpfops_wq);
}

static const struct bpf_func_proto *
bpf_ufq_get_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	return bpf_base_func_proto(func_id, prog);
}

static bool bpf_ufq_is_valid_access(int off, int size,
				    enum bpf_access_type type,
				    const struct bpf_prog *prog,
				    struct bpf_insn_access_aux *info)
{
	if (type != BPF_READ)
		return false;
	if (off < 0 || off >= sizeof(__u64) * MAX_BPF_FUNC_ARGS)
		return false;
	if (off % size != 0)
		return false;

	/*
	 * btf_ctx_access() treats pointers that are not "pointer to struct"
	 * as scalars (no reg_type), so loading pointers like merge_req()'s
	 * int *type or merge_bio()'s bool *merged from ctx leaves a SCALAR
	 * and stores through them fail verification. Model both as writable
	 * buffers.
	 */
	if (size == sizeof(__u64) && prog->aux->attach_func_name &&
	    ((!strcmp(prog->aux->attach_func_name, "merge_req") && off == 16) ||
	     (!strcmp(prog->aux->attach_func_name, "merge_bio") && off == 24))) {
		if (!btf_ctx_access(off, size, type, prog, info))
			return false;
		info->reg_type = PTR_TO_BUF;
		return true;
	}

	return btf_ctx_access(off, size, type, prog, info);
}

static const struct bpf_verifier_ops bpf_ufq_verifier_ops = {
	.get_func_proto = bpf_ufq_get_func_proto,
	.is_valid_access = bpf_ufq_is_valid_access,
};

static int bpf_ufq_init_member(const struct btf_type *t,
			       const struct btf_member *member,
			       void *kdata, const void *udata)
{
	const struct ufq_iosched_ops *uops = udata;
	struct ufq_iosched_ops *ops = kdata;
	u32 moff = __btf_member_bit_offset(t, member) / 8;
	int ret;

	switch (moff) {
	case offsetof(struct ufq_iosched_ops, name):
		ret = bpf_obj_name_cpy(ops->name, uops->name,
				       sizeof(ops->name));
		if (ret < 0)
			return ret;
		if (ret == 0)
			return -EINVAL;
		return 1;
	/* other var adding .... */
	}

	return 0;
}

static int bpf_ufq_check_member(const struct btf_type *t,
				const struct btf_member *member,
				const struct bpf_prog *prog)
{
	return 0;
}

static int bpf_ufq_enable(void *ops)
{
	ufq_ops = *(struct ufq_iosched_ops *)ops;
	atomic_set(&ufq_bpfops_enabled, 1);
	return 0;
}

static void bpf_ufq_disable(struct ufq_iosched_ops *ops)
{
	atomic_set(&ufq_bpfops_enabled, 0);
	wait_event(ufq_bpfops_wq, !atomic_read(&ufq_bpfops_users));
	memset(&ufq_ops, 0, sizeof(ufq_ops));
}

static int bpf_ufq_reg(void *kdata, struct bpf_link *link)
{
	return ufq_prepare_bpf_attach(bpf_ufq_enable, kdata);
}

static void bpf_ufq_unreg(void *kdata, struct bpf_link *link)
{
	bpf_ufq_disable(kdata);
	ufq_kick_all_hw_queues();
}

static int bpf_ufq_init(struct btf *btf)
{
	return 0;
}

static int bpf_ufq_update(void *kdata, void *old_kdata, struct bpf_link *link)
{
	/*
	 * UFQ does not support live-updating an already-attached BPF scheduler:
	 * partial failure during callback setup (e.g. init_sched) would be hard
	 * to reason about, and update can race with unregister/teardown.
	 */
	return -EOPNOTSUPP;
}

static int bpf_ufq_validate(void *kdata)
{
	return 0;
}

static int init_sched_stub(struct request_queue *q)
{
	return -EPERM;
}

static int exit_sched_stub(struct request_queue *q)
{
	return -EPERM;
}

static int insert_req_stub(struct request_queue *q, struct request *rq,
			   blk_insert_t flags)
{
	return 0;
}

static struct request *dispatch_req_stub(struct request_queue *q)
{
	return NULL;
}

static bool has_req_stub(struct request_queue *q, int rqs_count)
{
	return rqs_count > 0;
}

static void finish_req_stub(struct request *rq)
{
}

static struct request *merge_req_stub(struct request_queue *q, struct request *rq,
				      int *type)
{
	*type = ELEVATOR_NO_MERGE;
	return NULL;
}

static struct request *merge_bio_stub(struct request_queue *q, struct bio *bio,
				      unsigned int nr_segs, bool *merged)
{
	if (merged)
		*merged = false;

	return NULL;
}

static struct ufq_iosched_ops __bpf_ops_ufq_ops = {
	.init_sched		= init_sched_stub,
	.exit_sched		= exit_sched_stub,
	.insert_req		= insert_req_stub,
	.dispatch_req		= dispatch_req_stub,
	.has_req		= has_req_stub,
	.merge_req		= merge_req_stub,
	.finish_req		= finish_req_stub,
	.merge_bio		= merge_bio_stub,
};

static struct bpf_struct_ops bpf_iosched_ufq_ops = {
	.verifier_ops = &bpf_ufq_verifier_ops,
	.reg = bpf_ufq_reg,
	.unreg = bpf_ufq_unreg,
	.check_member = bpf_ufq_check_member,
	.init_member = bpf_ufq_init_member,
	.init = bpf_ufq_init,
	.update = bpf_ufq_update,
	.validate = bpf_ufq_validate,
	.name = "ufq_iosched_ops",
	.owner = THIS_MODULE,
	.cfi_stubs = &__bpf_ops_ufq_ops
};

int bpf_ufq_ops_init(void)
{
	return register_bpf_struct_ops(&bpf_iosched_ufq_ops, ufq_iosched_ops);
}
