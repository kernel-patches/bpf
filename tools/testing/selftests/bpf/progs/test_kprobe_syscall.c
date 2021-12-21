// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Hengqi Chen */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

const volatile pid_t my_pid = 0;
int domain = 0;
int type = 0;
int protocol = 0;
int fd = 0;

SEC("kprobe/__x64_sys_socket")
int BPF_KPROBE_SYSCALL(socket_enter, int d, int t, int p)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;

	if (pid != my_pid)
		return 0;

	domain = d;
	type = t;
	protocol = p;
	return 0;
}

SEC("kretprobe/__x64_sys_socket")
int BPF_KRETPROBE_SYSCALL(socket_exit, int ret)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;

	if (pid != my_pid)
		return 0;

	fd = ret;
	return 0;
}

char _license[] SEC("license") = "GPL";
