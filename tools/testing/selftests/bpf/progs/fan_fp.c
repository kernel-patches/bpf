// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpf_kfuncs.h"

struct __dentry_kptr_value {
	struct dentry __kptr * dentry;
};

/* subdir_root map holds a single dentry pointer to the subtree root.
 * This pointer is used to call bpf_is_subdir().
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct __dentry_kptr_value);
	__uint(max_entries, 1);
} subdir_root SEC(".maps");

/* inode_storage_map serves as cache for bpf_is_subdir(). inode local
 * storage has O(1) access time. So this is preferred over calling
 * bpf_is_subdir().
 */
struct {
	__uint(type, BPF_MAP_TYPE_INODE_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, int);
} inode_storage_map SEC(".maps");

unsigned long root_ino;
bool initialized;

/* This function initialize map subdir_root. The logic is a bit ungly.
 * First, user space sets root_ino. Then a fanotify event is triggered.
 * If the event dentry matches root_ino, we take a reference on the
 * dentry and save it in subdir_root map. The reference will be freed on
 * the termination of subdir_root map.
 */
static void initialize_subdir_root(struct fanotify_fastpath_event *fp_event)
{
	struct __dentry_kptr_value *v;
	struct dentry *dentry, *old;
	int zero = 0;

	if (initialized)
		return;

	dentry = bpf_fanotify_data_dentry(fp_event);
	if (!dentry)
		return;

	if (dentry->d_inode->i_ino != root_ino) {
		bpf_dput(dentry);
		return;
	}

	v = bpf_map_lookup_elem(&subdir_root, &zero);
	if (!v) {
		bpf_dput(dentry);
		return;
	}

	old = bpf_kptr_xchg(&v->dentry, dentry);
	if (old)
		bpf_dput(old);
	initialized = true;
}

int cache_hit;

/* bpf_fp_handler is sleepable, as it calls bpf_dput() */
SEC("struct_ops.s")
int BPF_PROG(bpf_fp_handler,
	     struct fsnotify_group *group,
	     struct fanotify_fastpath_hook *fp_hook,
	     struct fanotify_fastpath_event *fp_event)
{
	struct __dentry_kptr_value *v;
	struct dentry *dentry;
	int zero = 0;
	int *value;
	int ret;

	initialize_subdir_root(fp_event);

	/* Before the subdir_root map is initialized, send all events to
	 * user space.
	 */
	if (!initialized)
		return FAN_FP_RET_SEND_TO_USERSPACE;

	dentry = bpf_fanotify_data_dentry(fp_event);
	if (!dentry)
		return FAN_FP_RET_SEND_TO_USERSPACE;

	/* If inode_storage_map has cached value, just return it */
	value = bpf_inode_storage_get(&inode_storage_map, dentry->d_inode, 0, 0);
	if (value) {
		bpf_dput(dentry);
		cache_hit++;
		return *value;
	}

	/* Hold rcu read lock for bpf_is_subdir */
	bpf_rcu_read_lock();
	v = bpf_map_lookup_elem(&subdir_root, &zero);
	if (!v || !v->dentry) {
		/* This shouldn't happen, but we need this to pass
		 * the verifier.
		 */
		ret = FAN_FP_RET_SEND_TO_USERSPACE;
		goto out;
	}

	if (bpf_is_subdir(dentry, v->dentry))
		ret = FAN_FP_RET_SEND_TO_USERSPACE;
	else
		ret = FAN_FP_RET_SKIP_EVENT;
out:
	bpf_rcu_read_unlock();

	/* Save current result to the inode_storage_map */
	value = bpf_inode_storage_get(&inode_storage_map, dentry->d_inode, 0,
				      BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (value)
		*value = ret;
	bpf_dput(dentry);
	return ret;
}

SEC("struct_ops")
int BPF_PROG(bpf_fp_init, struct fanotify_fastpath_hook *hook, const char *args)
{
	return 0;
}

SEC("struct_ops")
void BPF_PROG(bpf_fp_free, struct fanotify_fastpath_hook *hook)
{
}

SEC(".struct_ops.link")
struct fanotify_fastpath_ops bpf_fanotify_fastpath_ops = {
	.fp_handler = (void *)bpf_fp_handler,
	.fp_init = (void *)bpf_fp_init,
	.fp_free = (void *)bpf_fp_free,
	.name = "_tmp_test_sub_tree",
};

char _license[] SEC("license") = "GPL";
