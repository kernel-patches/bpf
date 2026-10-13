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
int retry_flags;	/* pos flags at the end of the lockless walks: 0 unless RETRY */
int ref_flags;		/* pos flags seen by the referenced walk */
int end_flags;		/* flags after a referenced loop ended: 0 unless NOMEM */
int second_len;		/* d_path length of the walk's second position */
int first_len;		/* d_path length of the first position, after the walk */
int escalated_len;	/* d_path length of the escalated position */
int escalate_err;	/* bpf_path_ancestors_legitimize() result */
char second_path[256];
char first_path[256];
char escalated_path[256];

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
	struct path *pos, *first = NULL;

	/*
	 * Keep first's init opaque: gcc-bpf otherwise folds it into a
	 * preceding loop's exit value, which the verifier cannot track.
	 */
	barrier_var(first);

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
	 * stays valid past the step that yielded it - the first one is held
	 * across the rest of the walk and used only once the walk is gone.
	 */
	bpf_iter_path_ancestors_new(&it, (struct path *)dir, 0);
	while ((pos = bpf_iter_path_ancestors_next(&it))) {
		ref_count++;
		ref_flags |= bpf_path_ancestors_pos_flags(&it);
		if (!first) {
			first = pos;
			continue;
		}
		if (ref_count == 2)
			second_len = bpf_path_d_path(pos, second_path,
						     sizeof(second_path));
		bpf_path_put(pos);
	}
	/* NULL from an allocation failure, not the root, surfaces here. */
	end_flags |= bpf_path_ancestors_pos_flags(&it);
	bpf_iter_path_ancestors_destroy(&it);
	/*
	 * The walk's own references moved on and the iterator is destroyed:
	 * the acquired reference is all that keeps the first position alive.
	 */
	if (first) {
		first_len = bpf_path_d_path(first, first_path,
					    sizeof(first_path));
		bpf_path_put(first);
	}

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

	/*
	 * Out of the RCU critical section.  The resumed iteration's first
	 * position is the escalated one, kept alive by the reference the
	 * iteration hands out, so sleepable work can run on it.
	 */
	while ((pos = bpf_iter_path_ancestors_next(&it))) {
		hybrid_count++;
		if (hybrid_count == 3)
			escalated_len = bpf_path_d_path(pos, escalated_path,
							sizeof(escalated_path));
		bpf_path_put(pos);
	}
	end_flags |= bpf_path_ancestors_pos_flags(&it);
	bpf_iter_path_ancestors_destroy(&it);
	return 0;
}
