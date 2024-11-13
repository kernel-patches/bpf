// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef EBUSY
#define EBUSY 16
#endif

char _license[] SEC("license") = "GPL";
int nr_del_errs;
int test_pid;

struct {
	__uint(type, BPF_MAP_TYPE_INODE_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, long);
} inode_map SEC(".maps");

/* inode_storage_lookup is not an ideal hook for recursion tests, as it
 * is static and more likely to get inlined. However, there isn't a
 * better function for the test. This is because we need to call
 * bpf_inode_storage_* helpers with an inode intput. Unlike task local
 * storage, for which we can use bpf_get_current_task_btf() to get task
 * pointer with BTF, for inode local storage, we need the get the inode
 * pointer from function arguments. Other functions, such as,
 * bpf_local_storage_get() does not take inode as input.
 */
SEC("fentry/inode_storage_lookup")
int BPF_PROG(trace_inode_storage_lookup, struct inode *inode)
{
	struct task_struct *task = bpf_get_current_task_btf();
	long *ptr;
	int err;

	if (!test_pid || task->pid != test_pid)
		return 0;

	/* This doesn't have BPF_LOCAL_STORAGE_GET_F_CREATE, so it will
	 * not trigger on the first call of bpf_inode_storage_get() below.
	 *
	 * This is called twice, recursion_misses += 2.
	 */
	ptr = bpf_inode_storage_get(&inode_map, inode, 0, 0);
	if (ptr) {
		*ptr += 1;

		/* This is called once, recursion_misses += 1. */
		err = bpf_inode_storage_delete(&inode_map, inode);
		if (err == -EBUSY)
			nr_del_errs++;
	}

	return 0;
}

SEC("fentry/security_inode_mkdir")
int BPF_PROG(trace_inode_mkdir, struct inode *dir,
	     struct dentry *dentry,
	     int mode)
{
	struct task_struct *task = bpf_get_current_task_btf();
	long *ptr;

	if (!test_pid || task->pid != test_pid)
		return 0;

	/* Trigger trace_inode_storage_lookup, the first time */
	ptr = bpf_inode_storage_get(&inode_map, dir, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);

	/* trace_inode_storage_lookup cannot get ptr, so *ptr is 0.
	 * Set ptr to 200.
	 */
	if (ptr && !*ptr)
		*ptr = 200;

	/* Trigger trace_inode_storage_lookup, the second time.
	 * trace_inode_storage_lookup can now get ptr and increase the
	 * value. Now the value is 201.
	 */
	bpf_inode_storage_get(&inode_map, dir, 0,
			      BPF_LOCAL_STORAGE_GET_F_CREATE);

	return 0;

}
