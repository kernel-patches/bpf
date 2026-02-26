// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpf_misc.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} pid_map SEC(".maps");

static __always_inline int pid_ok(void)
{
	__u32 key = 0, *expected_pid;

	expected_pid =  bpf_map_lookup_elem(&pid_map, &key);
	if (!expected_pid ||
	    *expected_pid != (bpf_get_current_pid_tgid() >> 32))
		return 0;
	return 1;
}

static struct sockaddr_in old;

static int handle_sys_connect_common(struct sockaddr_in *uservaddr)
{
	struct sockaddr_in new;

	bpf_probe_read_user(&old, sizeof(old), uservaddr);
	__builtin_memset(&new, 0xab, sizeof(new));
	bpf_probe_write_user(uservaddr, &new, sizeof(new));

	return 0;
}

SEC("ksyscall/connect")
int BPF_KSYSCALL(handle_sys_connect, int fd, struct sockaddr_in *uservaddr,
		 int addrlen)
{
	if (!pid_ok())
		return 0;
	return handle_sys_connect_common(uservaddr);
}

#if defined(bpf_target_s390)
#ifndef SYS_CONNECT
#define SYS_CONNECT 3
#endif

SEC("ksyscall/socketcall")
int BPF_KSYSCALL(handle_sys_socketcall, int call, unsigned long *args)
{
	if (call == SYS_CONNECT) {
		struct sockaddr_in *uservaddr;

		if (!pid_ok())
			return 0;
		bpf_probe_read_user(&uservaddr, sizeof(uservaddr), &args[1]);
		return handle_sys_connect_common(uservaddr);
	}

	return 0;
}
#endif

char _license[] SEC("license") = "GPL";
