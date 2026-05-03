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
#include <trace/events/block.h>
#include "blk.h"
#include "ufq-iosched.h"

__bpf_kfunc_start_defs();

__bpf_kfunc struct request *bpf_request_acquire(struct request *rq)
{
	if (req_ref_inc_not_zero(rq))
		return rq;
	return NULL;
}

__bpf_kfunc void bpf_request_release(struct request *rq)
{
	if (req_ref_put_and_test(rq))
		__blk_mq_free_request(rq);
}

__bpf_kfunc bool bpf_request_bio_try_merge(struct request *rq, struct bio *bio,
					   unsigned int nr_segs)
{
	struct blk_mq_ctx *ctx;
	bool merged;

	if (!rq || !bio)
		return false;

	ctx = rq->mq_ctx;
	if (!ctx || !rq->q || !bio->bi_bdev || !bio->bi_bdev->bd_disk ||
	    bio->bi_bdev->bd_disk->queue != rq->q)
		return false;

	spin_lock(&ctx->lock);
	merged = blk_attempt_bio_merge(rq->q, rq, bio, nr_segs, true) == BIO_MERGE_OK;
	spin_unlock(&ctx->lock);

	return merged;
}

__bpf_kfunc struct request *bpf_request_try_merge(struct request *rq, struct request *next)
{
	struct blk_mq_ctx *ctx;
	struct ufq_data *ufq;
	struct request *free;

	if (!rq || !next || !rq->q || rq->q != next->q)
		return NULL;

	ufq = rq->q->elevator->elevator_data;
	if (!ufq)
		return NULL;

	if (rq->mq_ctx != next->mq_ctx || rq->mq_hctx != next->mq_hctx)
		return NULL;

	ctx = rq->mq_ctx;
	if (!ctx)
		return NULL;

	spin_lock(&ctx->lock);
	free = bpf_attempt_merge(rq->q, rq, next);
	if (free) {
		if (rq->q->last_merge == free)
			rq->q->last_merge = NULL;
		list_del_init(&free->queuelist);
		atomic_dec(&ufq->rqs_count);
	}
	spin_unlock(&ctx->lock);

	return free;
}

__bpf_kfunc_end_defs();

#if defined(CONFIG_X86_KERNEL_IBT)
static const void * const __used __section(".discard.ibt_endbr_noseal")
__ibt_noseal_bpf_request_release = (void *)bpf_request_release;
#endif

BTF_KFUNCS_START(ufq_kfunc_set_ops)
BTF_ID_FLAGS(func, bpf_request_acquire, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_request_release, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_request_bio_try_merge, KF_SPIN_LOCK)
BTF_ID_FLAGS(func, bpf_request_try_merge, KF_SPIN_LOCK)
BTF_KFUNCS_END(ufq_kfunc_set_ops)

static const struct btf_kfunc_id_set bpf_ufq_kfunc_set = {
	.owner			= THIS_MODULE,
	.set			= &ufq_kfunc_set_ops,
};

BTF_ID_LIST(bpf_ufq_dtor_kfunc_ids)
BTF_ID(struct, request)
BTF_ID(func, bpf_request_release)

int bpf_ufq_kfunc_init(void)
{
	int ret;
	const struct btf_id_dtor_kfunc bpf_ufq_dtor_kfunc[] = {
		{
		  .btf_id       = bpf_ufq_dtor_kfunc_ids[0],
		  .kfunc_btf_id = bpf_ufq_dtor_kfunc_ids[1]
		},
	};

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS, &bpf_ufq_kfunc_set);
	if (ret)
		return ret;
	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &bpf_ufq_kfunc_set);
	if (ret)
		return ret;
	ret = register_btf_id_dtor_kfuncs(bpf_ufq_dtor_kfunc,
					  ARRAY_SIZE(bpf_ufq_dtor_kfunc),
					  THIS_MODULE);
	if (ret)
		return ret;

	return 0;
}
