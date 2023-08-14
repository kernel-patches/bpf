// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2023 Yafang Shao <laoar.shao@gmail.com> */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define CAP_SYS_ADMIN	21
#define CAP_PERFMON	38
#define CAP_BPF		39

extern bool bpf_current_capable(int cap) __ksym;
bool cap_sys_admin, cap_bpf, cap_perfmon;

int link_create_audit(union bpf_attr *attr)
{
	cap_bpf = bpf_current_capable(CAP_BPF);
	cap_perfmon = bpf_current_capable(CAP_PERFMON);
	cap_sys_admin = bpf_current_capable(CAP_SYS_ADMIN);
	return cap_sys_admin ? 0 : -1;
}

SEC("lsm/bpf")
int BPF_PROG(lsm_run, int cmd, union bpf_attr *attr, unsigned int size)
{
	if (cmd != BPF_LINK_CREATE)
		return 0;
	return link_create_audit(attr);
}

SEC("perf_event")
int BPF_PROG(perf_event_run)
{
	return 0;
}

char _license[] SEC("license") = "GPL";
