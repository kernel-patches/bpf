// SPDX-License-Identifier: GPL-2.0-only
#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

int monitored_pid;
bool check_enabled;
int deny;
int calls;
int observed_flags;
__u16 observed_mode;
char pathname[256];

SEC("lsm/file_open_name")
int BPF_PROG(check_name, const struct filename *name, const struct path *base, int flags, umode_t mode,
	     unsigned int lookup_flags, int ret)
{
	if (ret || !check_enabled || bpf_get_current_pid_tgid() >> 32 != monitored_pid)
		return ret;

	bpf_probe_read_kernel_str(pathname, sizeof(pathname), name->name);
	observed_flags = flags;
	observed_mode = mode;
	calls++;
	return deny ? -EPERM : 0;
}

char LICENSE[] SEC("license") = "GPL";
