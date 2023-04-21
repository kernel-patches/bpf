// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Bytedance */

#include <vmlinux.h>
#include <asm/unistd.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

#include "cgrp_kfunc_common.h"

const volatile int local_pid;
const volatile long cgid;
int remote_pid;

SEC("tp_btf/sys_enter")
int BPF_PROG(sysenter, struct pt_regs *regs, long id)
{
	struct cgroup *cgrp;

	if (id != __NR_getuid)
		return 0;

	if (local_pid != (bpf_get_current_pid_tgid() >> 32))
		return 0;

	cgrp = bpf_cgroup_from_id(cgid);
	if (!cgrp)
		return 0;

	if (!bpf_task_under_cgroup(cgrp, bpf_get_current_task_btf()))
		goto out;

	remote_pid = local_pid;

out:
	bpf_cgroup_release(cgrp);
	return 0;
}

char _license[] SEC("license") = "GPL";
