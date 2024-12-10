// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"
#include "task_kfunc_common.h"

char _license[] SEC("license") = "GPL";

int err, parent_pid, count;

extern const void pipefifo_fops __ksym;
extern const void socket_file_ops __ksym;

SEC("fentry/" SYS_PREFIX "sys_nanosleep")
int test_bpf_iter_task_file(void *ctx)
{
	struct bpf_iter_task_file task_file_it;
	struct bpf_iter_task_file_item *item;
	struct task_struct *task;

	task = bpf_get_current_task_btf();
	if (task->parent->pid != parent_pid)
		return 0;

	count++;

	bpf_rcu_read_lock();
	bpf_iter_task_file_new(&task_file_it, task);

	item = bpf_iter_task_file_next(&task_file_it);
	if (item == NULL) {
		err = 1;
		goto cleanup;
	}

	if (item->fd != 0) {
		err = 2;
		goto cleanup;
	}

	if (item->file->f_op != &pipefifo_fops) {
		err = 3;
		goto cleanup;
	}

	item = bpf_iter_task_file_next(&task_file_it);
	if (item == NULL) {
		err = 4;
		goto cleanup;
	}

	if (item->fd != 1) {
		err = 5;
		goto cleanup;
	}

	if (item->file->f_op != &pipefifo_fops) {
		err = 6;
		goto cleanup;
	}

	item = bpf_iter_task_file_next(&task_file_it);
	if (item == NULL) {
		err = 7;
		goto cleanup;
	}

	if (item->fd != 2) {
		err = 8;
		goto cleanup;
	}

	if (item->file->f_op != &socket_file_ops) {
		err = 9;
		goto cleanup;
	}

	item = bpf_iter_task_file_next(&task_file_it);
	if (item != NULL)
		err = 10;
cleanup:
	bpf_iter_task_file_destroy(&task_file_it);
	bpf_rcu_read_unlock();
	return 0;
}
