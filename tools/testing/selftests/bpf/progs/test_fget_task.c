// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"
#include "task_kfunc_common.h"

char _license[] SEC("license") = "GPL";

int err, test_fd1, test_fd2;

SEC("syscall")
int test_bpf_fget_task(void *ctx)
{
	struct task_struct *task;
	struct file *file;

	task = bpf_get_current_task_btf();
	if (task == NULL) {
		err = 1;
		return 0;
	}

	file = bpf_fget_task(task, test_fd1);
	if (file == NULL) {
		err = 2;
		return 0;
	}

	bpf_put_file(file);

	file = bpf_fget_task(task, test_fd2);
	if (file == NULL) {
		err = 3;
		return 0;
	}

	bpf_put_file(file);

	file = bpf_fget_task(task, 9999);
	if (file != NULL) {
		err = 4;
		bpf_put_file(file);
	}

	return 0;
}
