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

__bpf_kfunc_start_defs();

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
