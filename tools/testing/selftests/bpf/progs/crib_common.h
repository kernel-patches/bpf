/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __CRIB_COMMON_H
#define __CRIB_COMMON_H

#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

extern struct task_struct *bpf_task_from_vpid(s32 vpid) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;

struct bpf_iter_task_file;
extern int bpf_iter_task_file_new(struct bpf_iter_task_file *it,
		struct task_struct *task) __ksym;
extern struct file *bpf_iter_task_file_next(struct bpf_iter_task_file *it) __ksym;
extern int bpf_iter_task_file_get_fd(struct bpf_iter_task_file *it__iter) __ksym;
extern void bpf_iter_task_file_destroy(struct bpf_iter_task_file *it) __ksym;

extern struct file *bpf_fget_task(struct task_struct *task, unsigned int fd) __ksym;
extern unsigned int bpf_get_file_ops_type(struct file *file) __ksym;
extern void bpf_put_file(struct file *file) __ksym;

#endif /* __CRIB_COMMON_H */
