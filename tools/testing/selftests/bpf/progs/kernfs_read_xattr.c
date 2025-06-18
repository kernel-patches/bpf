// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "bpf_experimental.h"
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

char value[16];

__always_inline void read_xattr(struct cgroup *cgroup)
{
	struct bpf_dynptr value_ptr;

	bpf_dynptr_from_mem(value, sizeof(value), 0, &value_ptr);
	bpf_kernfs_read_xattr(cgroup->kn, "user.bpf_test",
			      &value_ptr);
}

SEC("lsm.s/socket_connect")
__failure __msg("R1 must be a rcu pointer")
int BPF_PROG(sleepable_missing_rcu_lock, struct file *f)
{
	u64 cgrp_id = bpf_get_current_cgroup_id();
	struct cgroup *cgrp;

	cgrp = bpf_cgroup_from_id(cgrp_id);
	if (!cgrp)
		return 0;

	/* Sleepable, so cgrp->kn is not trusted */
	read_xattr(cgrp);
	bpf_cgroup_release(cgrp);
	return 0;
}

SEC("lsm.s/socket_connect")
__success
int BPF_PROG(sleepable_with_rcu_lock, struct file *f)
{
	u64 cgrp_id = bpf_get_current_cgroup_id();
	struct cgroup *cgrp;

	bpf_rcu_read_lock();
	cgrp = bpf_cgroup_from_id(cgrp_id);
	if (!cgrp)
		goto out;

	/* In rcu read lock, so cgrp->kn is trusted */
	read_xattr(cgrp);
	bpf_cgroup_release(cgrp);
out:
	bpf_rcu_read_unlock();
	return 0;
}

SEC("lsm/socket_connect")
__success
int BPF_PROG(non_sleepable, struct file *f)
{
	u64 cgrp_id = bpf_get_current_cgroup_id();
	struct cgroup *cgrp;

	cgrp = bpf_cgroup_from_id(cgrp_id);
	if (!cgrp)
		return 0;

	/* non-sleepable, so cgrp->kn is trusted */
	read_xattr(cgrp);
	bpf_cgroup_release(cgrp);
	return 0;
}

SEC("lsm/socket_connect")
__success
int BPF_PROG(use_css_iter, struct file *f)
{
	u64 cgrp_id = bpf_get_current_cgroup_id();
	struct cgroup_subsys_state *css;
	struct cgroup *cgrp;

	cgrp = bpf_cgroup_from_id(cgrp_id);
	if (!cgrp)
		return 0;

	bpf_for_each(css, css, &cgrp->self, BPF_CGROUP_ITER_ANCESTORS_UP)
		read_xattr(css->cgroup);

	bpf_cgroup_release(cgrp);
	return 0;
}

SEC("lsm/socket_connect")
__success
int BPF_PROG(use_bpf_cgroup_ancestor, struct file *f)
{
	u64 cgrp_id = bpf_get_current_cgroup_id();
	struct cgroup *cgrp, *ancestor;

	cgrp = bpf_cgroup_from_id(cgrp_id);
	if (!cgrp)
		return 0;

	ancestor = bpf_cgroup_ancestor(cgrp, 1);
	if (!ancestor)
		goto out;
	/* non-sleepable, so cgrp->kn is trusted */
	read_xattr(cgrp);
	bpf_cgroup_release(ancestor);
out:
	bpf_cgroup_release(cgrp);
	return 0;
}
