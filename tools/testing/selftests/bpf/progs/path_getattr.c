// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_kfuncs.h"

char _license[] SEC("license") = "GPL";

__u32 monitored_tid;
__u32 request_mask;
__u32 calls;
int getattr_ret;

__u64 ino;
__u32 dev;
__s64 size;
__u32 mode;
__u32 uid;
__u32 gid;
__u32 result_mask;

SEC("lsm.s/inode_getattr")
int BPF_PROG(path_getattr, const struct path *path, int ret)
{
	struct kstat stat = {};

	if (ret || (__u32)bpf_get_current_pid_tgid() != monitored_tid || calls)
		return ret;
	calls++;
	getattr_ret = bpf_path_getattr(path, request_mask, 0, &stat, sizeof(stat));
	if (!getattr_ret) {
		ino = stat.ino;
		dev = stat.dev;
		size = stat.size;
		mode = stat.mode;
		uid = stat.uid.val;
		gid = stat.gid.val;
		result_mask = stat.result_mask;
	}
	return ret;
}
