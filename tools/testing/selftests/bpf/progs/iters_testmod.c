// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include "bpf_experimental.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "../bpf_testmod/bpf_testmod_kfunc.h"

char _license[] SEC("license") = "GPL";

SEC("raw_tp/sys_enter")
__success
int iter_next_trusted(const void *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct bpf_iter_task_vma vma_it;
	struct vm_area_struct *vma;

	bpf_iter_task_vma_new(&vma_it, task, 0);

	vma = bpf_iter_task_vma_next(&vma_it);

	if (vma == NULL)
		goto out;

	bpf_kfunc_valid_pointer_test(vma);
out:
	bpf_iter_task_vma_destroy(&vma_it);
	return 0;
}

SEC("raw_tp/sys_enter")
__failure __msg("Possibly NULL pointer passed to trusted arg0")
int iter_next_trusted_or_null(const void *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct bpf_iter_task_vma vma_it;
	struct vm_area_struct *vma;

	bpf_iter_task_vma_new(&vma_it, task, 0);

	vma = bpf_iter_task_vma_next(&vma_it);

	bpf_kfunc_valid_pointer_test(vma);

	bpf_iter_task_vma_destroy(&vma_it);
	return 0;
}
