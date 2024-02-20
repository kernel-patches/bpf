// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Google LLC. */

#ifndef _PATH_KFUNC_COMMON_H
#define _PATH_KFUNC_COMMON_H

#include <vmlinux.h>
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

struct path *bpf_get_task_fs_root(struct task_struct *task) __ksym;
struct path *bpf_get_task_fs_pwd(struct task_struct *task) __ksym;
void bpf_put_path(struct path *path) __ksym;

#endif /* _PATH_KFUNC_COMMON_H */
