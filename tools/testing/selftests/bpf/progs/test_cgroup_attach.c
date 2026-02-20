// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Christian Brauner <brauner@kernel.org> */

/*
 * BPF LSM cgroup attach policy: supervise cgroup migration.
 *
 * A designated process populates a denied_cgroups map with cgroup IDs
 * that should reject migration.  The cgroup_attach hook checks every
 * migration and returns -EPERM when the destination cgroup is denied.
 * It also records the last hook invocation into last_event for the
 * userspace test to verify arguments.
 */

#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct attach_event {
	__u32 task_pid;
	__u64 src_cgrp_id;
	__u64 dst_cgrp_id;
	__u8  threadgroup;
	__u32 hook_count;
};

/*
 * Cgroups that should reject migration.
 * Key:   cgroup kn->id (u64).
 * Value: unused marker.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, __u64);
	__type(value, __u8);
} denied_cgroups SEC(".maps");

/*
 * Record the last hook invocation for argument verification.
 * Key:   0.
 * Value: struct attach_event.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct attach_event);
} last_event SEC(".maps");

__u32 monitored_pid;

char _license[] SEC("license") = "GPL";

SEC("lsm.s/cgroup_attach")
int BPF_PROG(cgroup_attach, struct task_struct *task,
	     struct cgroup *src_cgrp, struct cgroup *dst_cgrp,
	     struct super_block *sb, bool threadgroup,
	     struct cgroup_namespace *ns)
{
	struct task_struct *current = bpf_get_current_task_btf();
	struct attach_event *evt;
	__u64 dst_id;
	__u32 key = 0;

	dst_id = BPF_CORE_READ(dst_cgrp, kn, id);

	if (bpf_map_lookup_elem(&denied_cgroups, &dst_id))
		return -EPERM;

	if (!monitored_pid || current->tgid != monitored_pid)
		return 0;

	evt = bpf_map_lookup_elem(&last_event, &key);
	if (evt) {
		evt->task_pid = task->pid;
		evt->src_cgrp_id = BPF_CORE_READ(src_cgrp, kn, id);
		evt->dst_cgrp_id = dst_id;
		evt->threadgroup = threadgroup ? 1 : 0;
		evt->hook_count++;
	}

	return 0;
}
