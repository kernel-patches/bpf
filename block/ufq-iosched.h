/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 KylinSoft Corporation.
 * Copyright (c) 2026 Kaitao Cheng <chengkaitao@kylinos.cn>
 */
#ifndef _BLOCK_UFQ_IOSCHED_H
#define _BLOCK_UFQ_IOSCHED_H

#include <linux/types.h>
#include "elevator.h"
#include "blk-mq.h"

#ifndef BPF_IOSCHED_NAME_MAX
#define BPF_IOSCHED_NAME_MAX	16
#endif

/* For testing and debugging */
struct ufq_ops_stats {
	atomic_t dispatch_ok_count;
	atomic64_t dispatch_ok_sectors;
	atomic_t dispatch_null_count;
	atomic_t insert_ok_count;
	atomic64_t insert_ok_sectors;
	atomic_t insert_err_count;
	atomic_t merge_request_ok_count;
	atomic64_t merge_request_ok_sectors;
	atomic_t merge_bio_ok_count;
	atomic64_t merge_bio_ok_sectors;
	atomic_t finish_ok_count;
	atomic64_t finish_ok_sectors;
};

struct ufq_iosched_ops {
	int (*init_sched)(struct request_queue *q);
	int (*exit_sched)(struct request_queue *q);
	bool (*has_req)(struct request_queue *q, int rqs_count);
	int (*insert_req)(struct request_queue *q, struct request *rq,
			blk_insert_t flags);
	void (*finish_req)(struct request *rq);
	struct request *(*merge_req)(struct request_queue *q, struct request *rq,
			int *type);
	struct request *(*merge_bio)(struct request_queue *q, struct bio *bio,
			unsigned int nr_segs, bool *merged);
	struct request *(*dispatch_req)(struct request_queue *q);
	char name[BPF_IOSCHED_NAME_MAX];
};

struct ufq_data {
	struct request_queue *q;
	u32 async_depth;
	atomic_t rqs_count;
	struct list_head active_node;
	struct ufq_ops_stats ops_stats;
};

const struct ufq_iosched_ops *ufq_bpfops_tryget(void);
void ufq_bpfops_put(void);
void ufq_kick_all_hw_queues(void);
int ufq_prepare_bpf_attach(int (*enable)(void *kdata), void *kdata);

int bpf_ufq_ops_init(void);
int bpf_ufq_kfunc_init(void);

#endif /* _BLOCK_UFQ_IOSCHED_H */
