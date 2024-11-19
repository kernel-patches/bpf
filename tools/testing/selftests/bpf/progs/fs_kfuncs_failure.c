// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

char _license[] SEC("license") = "GPL";

SEC("syscall")
__failure __msg("Possibly NULL pointer passed to trusted arg0")
int bpf_fget_task_null_task(void *ctx)
{
	struct task_struct *task = NULL;

	bpf_fget_task(task, 1);

	return 0;
}

SEC("syscall")
__failure __msg("R1 must be referenced or trusted")
int bpf_fget_task_untrusted_task(void *ctx)
{
	struct task_struct *task;

	task = bpf_get_current_task_btf()->parent;

	bpf_fget_task(task, 1);

	return 0;
}
