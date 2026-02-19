// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Christian Brauner <brauner@kernel.org> */

/*
 * BPF LSM namespace sandbox: once you enter, you stay.
 *
 * A designated process creates namespaces (tracked via alloc).  When
 * any other process joins one of those namespaces it gets recorded in
 * locked_tasks.  From that point on that process cannot setns() into
 * any other namespace — it is locked in.  Task local storage is
 * automatically freed when the task exits.
 */

#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/*
 * Namespaces created by the monitored process.
 * Key:   namespace inode number.
 * Value: namespace type (CLONE_NEW* flag).
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u32);
} known_namespaces SEC(".maps");

/* PID of the process whose namespace creations are tracked. */
int monitor_pid;

/*
 * Task local storage: marks tasks that have entered a tracked namespace
 * and are now locked.
 */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, __u8);
} locked_tasks SEC(".maps");

char _license[] SEC("license") = "GPL";

/* Only the monitored process's namespace creations are tracked. */
SEC("lsm.s/namespace_alloc")
int BPF_PROG(ns_alloc, struct ns_common *ns)
{
	__u32 inum, ns_type;

	if ((bpf_get_current_pid_tgid() >> 32) != monitor_pid)
		return 0;

	inum = ns->inum;
	ns_type = ns->ns_type;
	bpf_map_update_elem(&known_namespaces, &inum, &ns_type, BPF_ANY);

	return 0;
}

/*
 * Enforce the lock-in policy for all tasks:
 * - Already locked?  Deny any setns.
 * - Entering a tracked namespace?  Lock the task and allow.
 * - Everything else passes through.
 */
SEC("lsm.s/namespace_install")
int BPF_PROG(ns_install, struct nsset *nsset, struct ns_common *ns)
{
	struct task_struct *task = bpf_get_current_task_btf();
	__u32 inum = ns->inum;

	if (bpf_task_storage_get(&locked_tasks, task, 0, 0))
		return -EPERM;

	if (bpf_map_lookup_elem(&known_namespaces, &inum))
		bpf_task_storage_get(&locked_tasks, task, 0,
				     BPF_LOCAL_STORAGE_GET_F_CREATE);

	return 0;
}

SEC("lsm/namespace_free")
void BPF_PROG(ns_free, struct ns_common *ns)
{
	__u32 inum = ns->inum;

	bpf_map_delete_elem(&known_namespaces, &inum);
}
