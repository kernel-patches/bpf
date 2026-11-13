// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "bpf_experimental.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

/* Result of a bpf_iter_css_next() call after the iterator was drained */
__u64 next_after_drain = -1;
int new_ret;
__u64 css_count;

struct cgroup *bpf_cgroup_from_id(u64 cgid) __ksym;
void bpf_cgroup_release(struct cgroup *p) __ksym;
void bpf_rcu_read_lock(void) __ksym;
void bpf_rcu_read_unlock(void) __ksym;

SEC("syscall")
int iter_css_next_after_drain(const void *ctx)
{
	u64 cg_id = bpf_get_current_cgroup_id();
	struct cgroup *cgrp = bpf_cgroup_from_id(cg_id);
	struct cgroup_subsys_state *pos;
	struct bpf_iter_css it;

	if (!cgrp) {
		new_ret = -1;
		return 0;
	}

	bpf_rcu_read_lock();
	new_ret = bpf_iter_css_new(&it, &cgrp->self,
				   BPF_CGROUP_ITER_DESCENDANTS_PRE);
	if (new_ret)
		goto out_destroy;

	while ((pos = bpf_iter_css_next(&it)))
		css_count++;

	/* Store the raw value; the verifier would remove a branch on it */
	next_after_drain = (__u64)bpf_iter_css_next(&it);

out_destroy:
	/* The destructor is called even when the constructor failed. */
	bpf_iter_css_destroy(&it);
	bpf_rcu_read_unlock();
	bpf_cgroup_release(cgrp);
	return 0;
}
