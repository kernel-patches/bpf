// SPDX-License-Identifier: GPL-2.0

#include <linux/btf.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/net.h>

/**
 * This enum will grow with the file types that CRIB supports for
 * checkpoint/restore.
 */
enum {
	FILE_OPS_UNKNOWN = 0
};

struct bpf_iter_task_file {
	__u64 __opaque[3];
} __aligned(8);

struct bpf_iter_task_file_kern {
	struct task_struct *task;
	struct file *file;
	int fd;
} __aligned(8);

__bpf_kfunc_start_defs();

/**
 * bpf_iter_task_file_new() - Initialize a new task file iterator for a task,
 * used to iterate over all files opened by a specified task
 *
 * @it: the new bpf_iter_task_file to be created
 * @task: a pointer pointing to a task to be iterated over
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
 * bpf_iter_task_file_next acquires a reference to the returned struct file.
 *
 * The reference to struct file acquired by the previous
 * bpf_iter_task_file_next() is released in the next bpf_iter_task_file_next(),
 * and the last reference is released in the last bpf_iter_task_file_next()
 * that returns NULL.
 *
 * @it: the bpf_iter_task_file to be checked
 *
 * @returns a pointer to the struct file of the next file if further files
 * are available, otherwise returns NULL
 */
__bpf_kfunc struct file *bpf_iter_task_file_next(struct bpf_iter_task_file *it)
{
	struct bpf_iter_task_file_kern *kit = (void *)it;

	if (kit->file)
		fput(kit->file);

	kit->fd++;

	rcu_read_lock();
	kit->file = task_lookup_next_fdget_rcu(kit->task, &kit->fd);
	rcu_read_unlock();

	return kit->file;
}

/**
 * bpf_iter_task_file_get_fd() - Get the file descriptor corresponding to
 * the file in the current iteration
 *
 * @it: the bpf_iter_task_file to be checked
 *
 * @returns the file descriptor
 */
__bpf_kfunc int bpf_iter_task_file_get_fd(struct bpf_iter_task_file *it__iter)
{
	struct bpf_iter_task_file_kern *kit = (void *)it__iter;

	return kit->fd;
}

/**
 * bpf_iter_task_file_destroy() - Destroy a bpf_iter_task_file
 *
 * If the iterator does not iterate to the end, then the last
 * struct file reference is released at this time.
 *
 * @it: the bpf_iter_task_file to be destroyed
 */
__bpf_kfunc void bpf_iter_task_file_destroy(struct bpf_iter_task_file *it)
{
	struct bpf_iter_task_file_kern *kit = (void *)it;

	if (kit->file)
		fput(kit->file);
}

/**
 * bpf_fget_task() - Get a pointer to the struct file corresponding to
 * the task file descriptor
 *
 * Note that this function acquires a reference to struct file.
 *
 * @task: the specified struct task_struct
 * @fd: the file descriptor
 *
 * @returns the corresponding struct file pointer if found,
 * otherwise returns NULL
 */
__bpf_kfunc struct file *bpf_fget_task(struct task_struct *task, unsigned int fd)
{
	struct file *file;

	file = fget_task(task, fd);
	return file;
}

/**
 * bpf_get_file_ops_type() - Determine what exactly this file is based on
 * the file operations, such as socket, eventfd, timerfd, pipe, etc
 *
 * This function will grow with the file types that CRIB supports for
 * checkpoint/restore.
 *
 * @file: a pointer to the struct file
 *
 * @returns the file operations type
 */
__bpf_kfunc unsigned int bpf_get_file_ops_type(struct file *file)
{
	return FILE_OPS_UNKNOWN;
}

__bpf_kfunc_end_defs();
