// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "crib_common.h"

char _license[] SEC("license") = "GPL";

int err, pid;

SEC("syscall")
int test_bpf_iter_task_file(void *ctx)
{
	struct bpf_iter_task_file task_file_it;
	struct task_struct *task;
	struct file *file;
	int fd;

	task = bpf_task_from_vpid(pid);
	if (task == NULL) {
		err = 1;
		return 0;
	}

	bpf_iter_task_file_new(&task_file_it, task);

	file = bpf_iter_task_file_next(&task_file_it);
	if (file == NULL) {
		err = 2;
		goto cleanup;
	}

	fd = bpf_iter_task_file_get_fd(&task_file_it);
	if (fd != 0) {
		err = 3;
		goto cleanup;
	}

	file = bpf_iter_task_file_next(&task_file_it);
	if (file == NULL) {
		err = 4;
		goto cleanup;
	}

	fd = bpf_iter_task_file_get_fd(&task_file_it);
	if (fd != 1) {
		err = 5;
		goto cleanup;
	}

	file = bpf_iter_task_file_next(&task_file_it);
	if (file == NULL) {
		err = 6;
		goto cleanup;
	}

	fd = bpf_iter_task_file_get_fd(&task_file_it);
	if (fd != 2) {
		err = 7;
		goto cleanup;
	}

	file = bpf_iter_task_file_next(&task_file_it);
	if (file != NULL)
		err = 7;

cleanup:
	bpf_iter_task_file_destroy(&task_file_it);
	bpf_task_release(task);
	return 0;
}

SEC("syscall")
int test_bpf_fget_task(void *ctx)
{
	struct task_struct *task;
	struct file *file;

	task = bpf_task_from_vpid(pid);
	if (task == NULL) {
		err = 1;
		return 0;
	}

	file = bpf_fget_task(task, 0);
	if (file == NULL) {
		err = 2;
		goto cleanup;
	}

	bpf_put_file(file);

	file = bpf_fget_task(task, 1);
	if (file == NULL) {
		err = 3;
		goto cleanup;
	}

	bpf_put_file(file);

	file = bpf_fget_task(task, 2);
	if (file == NULL) {
		err = 4;
		goto cleanup;
	}

	bpf_put_file(file);

	file = bpf_fget_task(task, 3);
	if (file != NULL) {
		err = 5;
		bpf_put_file(file);
	}
cleanup:
	bpf_task_release(task);
	return 0;
}
