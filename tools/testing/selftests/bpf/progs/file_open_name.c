// SPDX-License-Identifier: GPL-2.0-only
#include "vmlinux.h"
#include <errno.h>
#include <linux/limits.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_experimental.h"

#define LOOKUP_RCU (1U << 8)

int monitored_pid;
bool check_enabled;
int deny;
bool require_ref;
int calls;
int rcu_calls;
int observed_flags;
__u16 observed_mode;
char pathname[256];
__u64 base_ino;
int base_path_ret;
char base_path[PATH_MAX];

SEC("lsm/file_open_name")
int BPF_PROG(check_name, const struct filename *name,
	     const struct path *base, int flags, umode_t mode,
	     unsigned int lookup_flags, int ret)
{
	if (ret || !check_enabled || bpf_get_current_pid_tgid() >> 32 != monitored_pid)
		return ret;

	bpf_probe_read_kernel_str(pathname, sizeof(pathname), name->name);
	base_ino = base->dentry->d_inode->i_ino;
	base_path_ret = bpf_path_d_path(base, base_path, sizeof(base_path));
	observed_flags = flags;
	observed_mode = mode;
	calls++;
	if (lookup_flags & LOOKUP_RCU) {
		rcu_calls++;
		if (require_ref)
			return -ECHILD;
	}
	return deny ? -EPERM : 0;
}

char LICENSE[] SEC("license") = "GPL";
