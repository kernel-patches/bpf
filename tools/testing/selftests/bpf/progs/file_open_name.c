// SPDX-License-Identifier: GPL-2.0-only
#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define LOOKUP_RCU (1U << 8)

__u64 pidns_dev;
__u64 pidns_ino;
__u32 monitored_tgid;
bool check_enabled;
bool deny;
bool require_ref;
int calls;
int rcu_calls;
__u64 base_ino;
int observed_flags;
__u16 observed_mode;
char pathname[256];

SEC("lsm/file_open_name")
int BPF_PROG(check_name, const struct filename *name, const struct path *base,
	     int flags, umode_t mode, unsigned int lookup_flags, int ret)
{
	struct bpf_pidns_info nsdata;

	if (ret || !check_enabled)
		return ret;
	if (bpf_get_ns_current_pid_tgid(pidns_dev, pidns_ino, &nsdata, sizeof(nsdata)))
		return ret;
	if (nsdata.tgid != monitored_tgid)
		return ret;

	calls++;
	if (lookup_flags & LOOKUP_RCU) {
		rcu_calls++;
		if (require_ref)
			return -ECHILD;
	}

	bpf_probe_read_kernel_str(pathname, sizeof(pathname), name->name);
	base_ino = base->dentry->d_inode->i_ino;
	observed_flags = flags;
	observed_mode = mode;
	return deny ? -EPERM : 0;
}

char LICENSE[] SEC("license") = "GPL";
