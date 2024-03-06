// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Google LLC. */

#ifndef _MM_KFUNC_COMMON_H
#define _MM_KFUNC_COMMON_H

#include <vmlinux.h>
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_misc.h"

struct mm_struct *bpf_task_mm_grab(struct task_struct *task) __ksym;
void bpf_mm_drop(struct mm_struct *mm) __ksym;

char _license[] SEC("license") = "GPL";

#endif /* _MM_KFUNC_COMMON_H */
