// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "../bpf_testmod/bpf_testmod_kfunc.h"

char _license[] SEC("license") = "GPL";

struct task_struct *bpf_task_from_pid(s32 pid) __ksym;
void bpf_task_release(struct task_struct *p) __ksym;

/* The following test cases are only used to test KF_OBTAIN
 * and are not related to actual usage scenarios.
 */

SEC("syscall")
__failure __msg("must be referenced or trusted")
int BPF_PROG(kfunc_obtain_not_trusted)
{
	struct task_struct *cur_task, *untrusted_task;

	cur_task = bpf_get_current_task_btf();
	untrusted_task = bpf_get_untrusted_task_test(cur_task);

	bpf_kfunc_obtain_test(untrusted_task);

	return 0;
}

SEC("syscall")
__success
int BPF_PROG(kfunc_obtain_trusted)
{
	struct task_struct *cur_task, *trusted_task;
	struct mm_struct *mm;
	int map_count = 0;

	cur_task = bpf_get_current_task_btf();
	trusted_task = bpf_task_from_pid(cur_task->pid);
	if (trusted_task == NULL)
		return 0;

	mm = bpf_kfunc_obtain_test(trusted_task);

	map_count = mm->map_count;

	bpf_task_release(trusted_task);

	return map_count;
}

SEC("syscall")
__failure __msg("invalid mem access 'scalar'")
int BPF_PROG(kfunc_obtain_use_after_release)
{
	struct task_struct *cur_task, *trusted_task;
	struct mm_struct *mm;
	int map_count = 0;

	cur_task = bpf_get_current_task_btf();
	trusted_task = bpf_task_from_pid(cur_task->pid);
	if (trusted_task == NULL)
		return 0;

	mm = bpf_kfunc_obtain_test(trusted_task);

	bpf_task_release(trusted_task);

	map_count = mm->map_count;

	return map_count;
}
