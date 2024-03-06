// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Google LLC. */

#ifndef _FILE_KFUNC_COMMON_H
#define _FILE_KFUNC_COMMON_H

#include <vmlinux.h>
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_misc.h"

struct mm_struct *bpf_task_mm_grab(struct task_struct *task) __ksym;
void bpf_mm_drop(struct mm_struct *mm) __ksym;

struct file *bpf_get_task_exe_file(struct task_struct *task) __ksym;
struct file *bpf_get_mm_exe_file(struct mm_struct *mm) __ksym;
void bpf_put_file(struct file *f) __ksym;

char _license[] SEC("license") = "GPL";

#endif /* _FILE_KFUNC_COMMON_H */
