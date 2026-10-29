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

struct bpf_file_stat output;

SEC("lsm.s/inode_getattr")
int BPF_PROG(path_getattr, const struct path *path, int ret)
{
	if (ret || (__u32)bpf_get_current_pid_tgid() != monitored_tid || calls)
		return ret;
	calls++;
	getattr_ret = bpf_path_getattr(path, request_mask, 0, &output, sizeof(output));
	return ret;
}
