// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <sys/types.h>

struct sys_enter_write_args {
	unsigned long long pad;
	int syscall_nr;
	int pad1; /* 4 byte hole */
	unsigned int fd;
	int pad2; /* 4 byte hole */
	const char *buf;
	size_t count;
};

pid_t pid = 0;
long ret = 0;
char buf[256] = {};

SEC("tracepoint/syscalls/sys_enter_write")
int on_write(struct sys_enter_write_args *ctx)
{
	if (pid != (bpf_get_current_pid_tgid() >> 32))
		return 0;

	ret = bpf_probe_read_user_str(buf, sizeof(buf), ctx->buf);

	return 0;
}

char _license[] SEC("license") = "GPL";
