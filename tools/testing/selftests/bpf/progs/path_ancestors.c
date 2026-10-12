// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Justin Suess */

#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_kfuncs.h"

char _license[] SEC("license") = "GPL";

__u32 monitored_pid;

int rcu_count;		/* positions seen by the pure lockless walk */
int rcu_ns_count;	/* ditto, from the non-sleepable program */
int ref_count;		/* positions seen by the pure referenced walk */
int hybrid_count;	/* positions seen by the lockless+escalate walk */
int retry_flags;	/* BPF_PATH_ANCESTORS_RETRY observations */
int ref_flags;		/* pos flags seen by the referenced walk */
int second_len;		/* d_path length of the walk's second position */
int xattr_ret;		/* xattr read at the escalated position */
int escalated_len;	/* d_path length of the escalated position */
int escalate_err;	/* bpf_path_ancestors_legitimize() result */
int test_err;
char second_path[256];
char escalated_path[256];
char xattr_value[16];

static bool monitored(void)
{
	return (bpf_get_current_pid_tgid() >> 32) == monitored_pid;
}

/*
 * Lockless walk from a non-sleepable program: the RCU critical section is
 * implicit, no bpf_rcu_read_lock() needed.
 */
SEC("lsm/path_mkdir")
int BPF_PROG(rcu_nonsleepable, const struct path *dir, struct dentry *dentry,
	     umode_t mode)
{
	struct bpf_iter_path_ancestors_rcu rit;

	if (!monitored())
		return 0;

	bpf_iter_path_ancestors_rcu_new(&rit, (struct path *)dir, 0);
	while (bpf_iter_path_ancestors_rcu_next(&rit))
		rcu_ns_count++;
	retry_flags |= bpf_path_ancestors_rcu_pos_flags(&rit);
	bpf_iter_path_ancestors_rcu_destroy(&rit);
	return 0;
}

SEC("lsm.s/path_mkdir")
int BPF_PROG(walk_modes, const struct path *dir, struct dentry *dentry,
	     umode_t mode)
{
	struct bpf_iter_path_ancestors_rcu rit;
	struct bpf_iter_path_ancestors it;
	struct bpf_dynptr value_ptr;
	struct path *pos;

	if (!monitored())
		return 0;

	/*
	 * Mode 1: pure lockless, under an explicit RCU critical section.
	 * Positions are borrowed, so nothing is released here.
	 */
	bpf_rcu_read_lock();
	bpf_iter_path_ancestors_rcu_new(&rit, (struct path *)dir, 0);
	while (bpf_iter_path_ancestors_rcu_next(&rit))
		rcu_count++;
	retry_flags |= bpf_path_ancestors_rcu_pos_flags(&rit);
	bpf_iter_path_ancestors_rcu_destroy(&rit);
	bpf_rcu_read_unlock();

	/*
	 * Mode 2: pure referenced.  Every position comes acquired, so it
	 * stays valid for sleepable work and past the step that yielded it.
	 */
	bpf_iter_path_ancestors_new(&it, (struct path *)dir, 0);
	while ((pos = bpf_iter_path_ancestors_next(&it))) {
		ref_count++;
		ref_flags |= bpf_path_ancestors_pos_flags(&it);
		if (ref_count == 2)
			second_len = bpf_path_d_path(pos, second_path,
						     sizeof(second_path));
		bpf_path_put(pos);
	}
	bpf_iter_path_ancestors_destroy(&it);

	/*
	 * Mode 3: hybrid.  Walk lockless to the second position, then hand
	 * that position over to a referenced iteration which resumes there.
	 */
	bpf_rcu_read_lock();
	bpf_iter_path_ancestors_rcu_new(&rit, (struct path *)dir, 0);
	while (bpf_iter_path_ancestors_rcu_next(&rit)) {
		hybrid_count++;
		if (hybrid_count == 2)
			break;
	}
	escalate_err = bpf_path_ancestors_legitimize(&it, &rit);
	retry_flags |= bpf_path_ancestors_rcu_pos_flags(&rit);
	bpf_iter_path_ancestors_rcu_destroy(&rit);
	bpf_rcu_read_unlock();

	if (escalate_err)
		test_err = 1;

	/*
	 * Out of the RCU critical section.  The resumed iteration's first
	 * position is the escalated one, kept alive by the reference the
	 * iteration hands out, so sleepable work can run on it.
	 */
	while ((pos = bpf_iter_path_ancestors_next(&it))) {
		hybrid_count++;
		if (hybrid_count == 3) {
			escalated_len = bpf_path_d_path(pos, escalated_path,
							sizeof(escalated_path));
			bpf_dynptr_from_mem(xattr_value, sizeof(xattr_value),
					    0, &value_ptr);
			/* A trusted path's dentry is trusted, never NULL. */
			xattr_ret = bpf_get_dentry_xattr(pos->dentry,
							 "user.walk",
							 &value_ptr);
		}
		bpf_path_put(pos);
	}
	bpf_iter_path_ancestors_destroy(&it);
	return 0;
}
