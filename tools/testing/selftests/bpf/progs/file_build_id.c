// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/string.h>

char _license[] SEC("license") = "GPL";

int pid;
u32 build_id_size;
char build_id[20];

SEC("tp_btf/sched_process_exec")
int BPF_PROG(prog, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
	int cur_pid = bpf_get_current_pid_tgid() >> 32;
	struct build_id *bid;

	if (pid != cur_pid)
		return 0;

	if (!bprm->file || !bprm->file->f_bid)
		return 0;

	bid = bprm->file->f_bid;
	build_id_size = bid->sz;

	if (build_id_size > 20)
		return 0;

	memcpy(build_id, bid->data, 20);
	return 0;
}
