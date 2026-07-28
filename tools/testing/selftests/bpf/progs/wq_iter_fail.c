// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

char _license[] SEC("license") = "GPL";

/*
 * The workqueue and worker_pool open-coded iterators are KF_RCU_PROTECTED:
 * using them outside a bpf_rcu_read_lock() region must be rejected.
 */

SEC("?syscall")
__failure __msg("kernel func bpf_iter_workqueue_new requires RCU critical section protection")
int workqueue_iter_no_rcu(const void *ctx)
{
	struct workqueue_struct *wq;
	int n = 0;

	bpf_for_each(workqueue, wq)
		n++;
	return n;
}

SEC("?syscall")
__failure __msg("kernel func bpf_iter_worker_pool_new requires RCU critical section protection")
int worker_pool_iter_no_rcu(const void *ctx)
{
	struct worker_pool *pool;
	int n = 0;

	bpf_for_each(worker_pool, pool)
		n++;
	return n;
}
