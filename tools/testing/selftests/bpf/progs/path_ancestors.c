// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Justin Suess */

#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_kfuncs.h"

char _license[] SEC("license") = "GPL";

__u32 monitored_pid;

int ref_count;		/* positions seen by the pure referenced walk */
int ref_flags;		/* pos flags seen by the referenced walk */
int second_len;		/* d_path length of the walk's second position */
char second_path[256];

static bool monitored(void)
{
	return (bpf_get_current_pid_tgid() >> 32) == monitored_pid;
}

SEC("lsm.s/path_mkdir")
int BPF_PROG(walk_modes, const struct path *dir, struct dentry *dentry,
	     umode_t mode)
{
	struct bpf_iter_path_ancestors it;
	struct path *pos;

	if (!monitored())
		return 0;

	/*
	 * Referenced walk: every position comes acquired, so it stays valid
	 * for sleepable work and past the step that yielded it.
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
	return 0;
}
