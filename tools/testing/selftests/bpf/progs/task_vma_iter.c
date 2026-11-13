// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "bpf_experimental.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

/* Result of a bpf_iter_task_vma_next() call after the iterator was drained */
__u64 next_after_drain = -1;
__u64 last_end;
__u64 drain_done;
__u64 go;
int new_ret;
int go_seen;
__u64 vma_count;

static long wait_for_go(u32 index, void *ctx)
{
	return go ? 1 : 0;
}

SEC("syscall")
int iter_task_vma_next_after_drain(const void *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct bpf_iter_task_vma it;
	struct vm_area_struct *vma;

	new_ret = bpf_iter_task_vma_new(&it, task, 0);
	if (new_ret) {
		drain_done = 1;
		go = 1;
		goto out;
	}

	while ((vma = bpf_iter_task_vma_next(&it))) {
		vma_count++;
		last_end = vma->vm_end;
	}

	/* Let user space map a new VMA at last_end before the extra next(). */
	drain_done = 1;
	bpf_loop(1000000, wait_for_go, NULL, 0);
	go_seen = go;

	/* Store the raw value; the verifier would remove a branch on it */
	next_after_drain = (__u64)bpf_iter_task_vma_next(&it);

out:
	/* The destructor is called even when the constructor failed. */
	bpf_iter_task_vma_destroy(&it);
	return 0;
}
