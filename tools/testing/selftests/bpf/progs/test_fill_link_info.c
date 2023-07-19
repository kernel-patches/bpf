// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2023 Yafang Shao <laoar.shao@gmail.com> */

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>

SEC("kprobe")
int BPF_PROG(kprobe_run)
{
	return 0;
}

SEC("uprobe")
int BPF_PROG(uprobe_run)
{
	return 0;
}

SEC("tracepoint")
int BPF_PROG(tp_run)
{
	return 0;
}

char _license[] SEC("license") = "GPL";
