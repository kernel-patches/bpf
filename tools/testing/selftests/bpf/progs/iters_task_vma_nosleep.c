// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include "bpf_experimental.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

/* Negative test: sleepable call without release should be rejected */
SEC("?fentry.s/" SYS_PREFIX "sys_getpgid")
__failure __msg("sleepable helper bpf_copy_from_user#{{[0-9]+}} in nofault region")
int nosleep_iter_sleep_without_release(const void *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct vm_area_struct *vma;

	bpf_for_each(task_vma, vma, task, 0) {
		char buf[8];

		/* Attempt to call sleepable helper without releasing mmap_lock.
		 * Verifier should reject this.
		 */
		bpf_copy_from_user(&buf, sizeof(buf), (void *)vma->vm_start);
		break;
	}
	return 0;
}

/* Negative test: VMA access after release should be rejected */
SEC("?fentry.s/" SYS_PREFIX "sys_getpgid")
__failure __msg("invalid mem access 'scalar'")
int nosleep_iter_vma_access_after_release(const void *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct vm_area_struct *vma;
	__u64 val = 0;

	bpf_for_each(task_vma, vma, task, 0) {
		bpf_iter_task_vma_release(&___it);
		/* VMA pointer is now invalid. Accessing it should be rejected. */
		val = vma->vm_start;
		break;
	}
	__sink(val);
	return 0;
}

/* Positive test: release then sleepable call should succeed */
SEC("?fentry.s/" SYS_PREFIX "sys_getpgid")
__success
int nosleep_iter_release_then_sleep(const void *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct vm_area_struct *vma;

	bpf_for_each(task_vma, vma, task, 0) {
		__u64 start = vma->vm_start;
		char buf[8];

		bpf_iter_task_vma_release(&___it);
		bpf_copy_from_user(&buf, sizeof(buf), (void *)start);
		break;
	}
	return 0;
}

/* Negative test: double release should be rejected */
SEC("?fentry.s/" SYS_PREFIX "sys_getpgid")
__failure __msg("no acquired reference to release")
int nosleep_iter_double_release(const void *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct vm_area_struct *vma;

	bpf_for_each(task_vma, vma, task, 0) {
		bpf_iter_task_vma_release(&___it);
		bpf_iter_task_vma_release(&___it);
		break;
	}
	return 0;
}

/* Negative test: release without any prior _next acquire */
SEC("?fentry.s/" SYS_PREFIX "sys_getpgid")
__failure __msg("no acquired reference to release")
int nosleep_iter_release_without_acquire(const void *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct bpf_iter_task_vma it;

	bpf_iter_task_vma_new(&it, task, 0);
	/* No _next called, so no acquired reference exists */
	bpf_iter_task_vma_release(&it);
	bpf_iter_task_vma_destroy(&it);
	return 0;
}

/* Negative test: nested iterators, releasing inner should not allow sleeping
 * because the outer iterator still holds a nofault reference.
 */
SEC("?fentry.s/" SYS_PREFIX "sys_getpgid")
__failure __msg("sleepable helper bpf_copy_from_user#{{[0-9]+}} in nofault region")
int nosleep_iter_nested_release_inner(const void *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct vm_area_struct *vma_outer, *vma_inner;

	bpf_for_each(task_vma, vma_outer, task, 0) {
		bpf_for_each(task_vma, vma_inner, task, 0) {
			__u64 start = vma_inner->vm_start;
			char buf[8];

			bpf_iter_task_vma_release(&___it);
			/* Inner released, but outer still holds nofault ref.
			 * Sleeping should still be forbidden.
			 */
			bpf_copy_from_user(&buf, sizeof(buf), (void *)start);
			break;
		}
		break;
	}
	return 0;
}
