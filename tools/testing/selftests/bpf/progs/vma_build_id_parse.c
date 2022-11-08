// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#define BPF_BUILD_ID_SIZE 20

__u64 addr = 0;
pid_t target_pid = 0;
int find_addr_ret = -1;
int vma_build_id_parse_ret = -1;

unsigned char build_id[BPF_BUILD_ID_SIZE];

static long check_vma(struct task_struct *task, struct vm_area_struct *vma,
		      void *data)
{
	vma_build_id_parse_ret = bpf_vma_build_id_parse(vma, (char *) build_id);
	return 0;
}

SEC("fentry/bpf_fentry_test1")
int BPF_PROG(test1, int a)
{
	struct task_struct *task = bpf_get_current_task_btf();

	if (task->pid != target_pid)
		return 0;

	find_addr_ret = bpf_find_vma(task, addr, check_vma, NULL, 0);
	return 0;
}
