// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"
#include "task_kfunc_common.h"

char _license[] SEC("license") = "GPL";

SEC("syscall")
__failure __msg("expected uninitialized iter_task_file as arg #0")
int bpf_iter_task_file_new_inited_iter(void *ctx)
{
	struct bpf_iter_task_file task_file_it;
	struct task_struct *task;

	task = bpf_get_current_task_btf();

	bpf_iter_task_file_new(&task_file_it, task);

	bpf_iter_task_file_new(&task_file_it, task);

	bpf_iter_task_file_destroy(&task_file_it);
	return 0;
}

SEC("syscall")
__failure __msg("Possibly NULL pointer passed to trusted arg1")
int bpf_iter_task_file_new_null_task(void *ctx)
{
	struct bpf_iter_task_file task_file_it;
	struct task_struct *task = NULL;

	bpf_iter_task_file_new(&task_file_it, task);

	bpf_iter_task_file_destroy(&task_file_it);
	return 0;
}

SEC("syscall")
__failure __msg("R2 must be referenced or trusted")
int bpf_iter_task_file_new_untrusted_task(void *ctx)
{
	struct bpf_iter_task_file task_file_it;
	struct task_struct *task;

	task = bpf_get_current_task_btf()->parent;

	bpf_iter_task_file_new(&task_file_it, task);

	bpf_iter_task_file_destroy(&task_file_it);
	return 0;
}

SEC("syscall")
__failure __msg("Unreleased reference")
int bpf_iter_task_file_no_destory(void *ctx)
{
	struct bpf_iter_task_file task_file_it;
	struct task_struct *task;

	task = bpf_get_current_task_btf();

	bpf_iter_task_file_new(&task_file_it, task);

	return 0;
}

SEC("syscall")
__failure __msg("expected an initialized iter_task_file as arg #0")
int bpf_iter_task_file_next_uninit_iter(void *ctx)
{
	struct bpf_iter_task_file task_file_it;

	bpf_iter_task_file_next(&task_file_it);

	return 0;
}

SEC("syscall")
__failure __msg("expected an initialized iter_task_file as arg #0")
int bpf_iter_task_file_destroy_uninit_iter(void *ctx)
{
	struct bpf_iter_task_file task_file_it;

	bpf_iter_task_file_destroy(&task_file_it);

	return 0;
}
