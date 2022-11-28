// SPDX-License-Identifier: GPL-2.0

#include "bpf_iter.h"
#include <bpf/bpf_helpers.h>

#define BPF_BUILD_ID_SIZE 20

extern int bpf_vma_build_id_parse(struct vm_area_struct *vma, unsigned char *build_id,
				  size_t build_id__sz) __ksym;

char _license[] SEC("license") = "GPL";

uintptr_t address = 0;
__u32 pid = 0;
int size = -1;

static unsigned char build_id[BPF_BUILD_ID_SIZE];

SEC("iter/task_vma")
int vma_build_id(struct bpf_iter__task_vma *ctx)
{
	struct vm_area_struct *vma = ctx->vma;
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	int i;

	if (task == NULL || vma == NULL)
		return 0;

	if (task->tgid != pid)
		return 0;

	if (address < vma->vm_start || vma->vm_end < address)
		return 0;

	size = bpf_vma_build_id_parse(vma, build_id, sizeof(build_id));

	for (i = 0; i < BPF_BUILD_ID_SIZE; i++)
		BPF_SEQ_PRINTF(seq, "%02x", build_id[i]);
	return 0;
}
