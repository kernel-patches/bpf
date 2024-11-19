// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"
#include "task_kfunc_common.h"

char _license[] SEC("license") = "GPL";

int err, pid;

SEC("syscall")
int test_bpf_iter_task_file(void *ctx)
{
	struct bpf_iter_task_file task_file_it;
	struct bpf_iter_task_file_item *item;
	struct task_struct *task;

	task = bpf_task_from_vpid(pid);
	if (task == NULL) {
		err = 1;
		return 0;
	}

	bpf_rcu_read_lock();
	bpf_iter_task_file_new(&task_file_it, task);

	item = bpf_iter_task_file_next(&task_file_it);
	if (item == NULL) {
		err = 2;
		goto cleanup;
	}

	if (item->fd != 0) {
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

	item = bpf_iter_task_file_next(&task_file_it);
	if (item == NULL) {
		err = 6;
		goto cleanup;
	}

	if (item->fd != 2) {
		err = 7;
		goto cleanup;
	}

	item = bpf_iter_task_file_next(&task_file_it);
	if (item != NULL)
		err = 8;
cleanup:
	bpf_iter_task_file_destroy(&task_file_it);
	bpf_rcu_read_unlock();
	bpf_task_release(task);
	return 0;
}
