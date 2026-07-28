// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_experimental.h"

char _license[] SEC("license") = "GPL";

void bpf_rcu_read_lock(void) __ksym;
void bpf_rcu_read_unlock(void) __ksym;

/* Results, checked by userspace. */
int nr_workqueues;
int nr_worker_pools;
int nr_percpu_pools;
int nr_wq_seq;
int nr_pool_seq;
int nr_pending;

/* --- open-coded iterators (KF_RCU_PROTECTED) --- */

SEC("syscall")
int count_workqueues(const void *ctx)
{
	struct workqueue_struct *wq;
	int n = 0;

	bpf_rcu_read_lock();
	bpf_for_each(workqueue, wq)
		n++;
	bpf_rcu_read_unlock();

	nr_workqueues = n;
	return 0;
}

SEC("syscall")
int count_worker_pools(const void *ctx)
{
	struct worker_pool *pool;
	int n = 0, percpu = 0;

	bpf_rcu_read_lock();
	bpf_for_each(worker_pool, pool) {
		n++;
		if (pool->cpu >= 0)		/* per-CPU pool */
			percpu++;
	}
	bpf_rcu_read_unlock();

	nr_worker_pools = n;
	nr_percpu_pools = percpu;
	return 0;
}

/* --- seq_file iterators --- */

SEC("iter/workqueue")
int dump_workqueues(struct bpf_iter__workqueue *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct workqueue_struct *wq = ctx->wq;

	if (!wq)
		return 0;
	nr_wq_seq++;
	BPF_SEQ_PRINTF(seq, "%s\n", wq->name);
	return 0;
}

SEC("iter/worker_pool")
int dump_worker_pools(struct bpf_iter__worker_pool *ctx)
{
	struct worker_pool *pool = ctx->pool;

	if (!pool)
		return 0;
	nr_pool_seq++;
	return 0;
}

SEC("iter/workqueue_pending_work")
int dump_pending(struct bpf_iter__workqueue_pending_work *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct wq_pending_work_info *info = ctx->info;

	if (!info)			/* final call */
		return 0;

	nr_pending++;
	BPF_SEQ_PRINTF(seq, "pool %llu work 0x%llx func 0x%llx\n",
		       info->pool_id, info->work, info->func);
	return 0;
}
