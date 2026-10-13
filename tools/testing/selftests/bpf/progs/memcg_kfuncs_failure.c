// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

SEC("syscall")
__failure __msg("Unreleased reference")
int root_memcg_leak(void *ctx)
{
	struct mem_cgroup *memcg;

	memcg = bpf_get_root_mem_cgroup();
	if (!memcg)
		return 0;

	/* Missing bpf_put_mem_cgroup(). */
	return 0;
}

SEC("syscall")
__failure __msg("Possibly NULL pointer passed to trusted R1")
int root_memcg_no_null_check(void *ctx)
{
	struct mem_cgroup *memcg;

	memcg = bpf_get_root_mem_cgroup();
	/* bpf_get_root_mem_cgroup() is KF_RET_NULL. */
	bpf_mem_cgroup_usage(memcg);
	bpf_put_mem_cgroup(memcg);
	return 0;
}

SEC("iter.s/cgroup")
__failure __msg("calling kernel function bpf_proactive_reclaim is not allowed")
int proactive_reclaim_not_syscall(struct bpf_iter__cgroup *ctx)
{
	struct cgroup *cgrp = ctx->cgroup;
	struct mem_cgroup *memcg;

	if (!cgrp)
		return 0;

	memcg = bpf_get_mem_cgroup(&cgrp->self);
	if (!memcg)
		return 0;

	/* Only BPF_PROG_TYPE_SYSCALL may reclaim. */
	bpf_proactive_reclaim(memcg, 4096, -1);
	bpf_put_mem_cgroup(memcg);
	return 0;
}
