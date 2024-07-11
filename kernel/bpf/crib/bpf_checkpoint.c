// SPDX-License-Identifier: GPL-2.0
/*
 * Checkpoint/Restore In eBPF (CRIB): Checkpoint
 *
 * Author:
 *	Juntong Deng <juntong.deng@outlook.com>
 */

#include <linux/bpf_crib.h>
#include <linux/fdtable.h>

extern void bpf_file_release(struct file *file);

__bpf_kfunc_start_defs();

/**
 * bpf_iter_task_file_new() - Initialize a new task file iterator for a task,
 * used to iterate over all files opened by a specified task
 *
 * @it: The new bpf_iter_task_file to be created
 * @task: A pointer pointing to a task to be iterated over
 */
__bpf_kfunc int bpf_iter_task_file_new(struct bpf_iter_task_file *it,
		struct task_struct *task)
{
	struct bpf_iter_task_file_kern *kit = (void *)it;

	BUILD_BUG_ON(sizeof(struct bpf_iter_task_file_kern) > sizeof(struct bpf_iter_task_file));
	BUILD_BUG_ON(__alignof__(struct bpf_iter_task_file_kern) !=
		     __alignof__(struct bpf_iter_task_file));

	kit->task = task;
	kit->fd = -1;
	kit->file = NULL;

	return 0;
}

/**
 * bpf_iter_task_file_next() - Get the next file in bpf_iter_task_file
 *
 * bpf_iter_task_file_next() acquires a reference to the returned struct file.
 *
 * The reference to struct file acquired by the previous
 * bpf_iter_task_file_next() is released in the next bpf_iter_task_file_next(),
 * and the last reference is released in the last bpf_iter_task_file_next()
 * that returns NULL.
 *
 * @it: The bpf_iter_task_file to be checked
 *
 * @returns a pointer to the struct file of the next file if further files
 * are available, otherwise returns NULL.
 */
__bpf_kfunc struct file *bpf_iter_task_file_next(struct bpf_iter_task_file *it)
{
	struct bpf_iter_task_file_kern *kit = (void *)it;

	if (kit->file)
		bpf_file_release(kit->file);

	kit->fd++;

	rcu_read_lock();
	kit->file = task_lookup_next_fdget_rcu(kit->task, &kit->fd);
	rcu_read_unlock();

	return kit->file;
}

/**
 * bpf_iter_task_file_get_fd() - Get the file descriptor
 * corresponding to the file in the current iteration
 *
 * @it: The bpf_iter_task_file to be checked
 *
 * @returns the file descriptor
 */
__bpf_kfunc int bpf_iter_task_file_get_fd(struct bpf_iter_task_file *it)
{
	struct bpf_iter_task_file_kern *kit = (void *)it;

	return kit->fd;
}

/**
 * bpf_iter_task_file_destroy() - Destroy a bpf_iter_task_file
 *
 * If the iterator does not iterate to the end, then the last
 * struct file reference is released at this time.
 *
 * @it: The bpf_iter_task_file to be destroyed
 */
__bpf_kfunc void bpf_iter_task_file_destroy(struct bpf_iter_task_file *it)
{
	struct bpf_iter_task_file_kern *kit = (void *)it;

	if (kit->file)
		bpf_file_release(kit->file);
}

__bpf_kfunc_end_defs();
