// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Google LLC. */

#ifndef _D_PATH_COMMON_H
#define _D_PATH_COMMON_H

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_misc.h"

#define MAX_PATH_LEN 128
#define MAX_FILES 8

int bpf_path_d_path(struct path *path, char *buf, int buflen) __ksym;

pid_t my_pid = 0;

__u32 cnt_stat = 0;
__u32 cnt_close = 0;

char paths_stat[MAX_FILES][MAX_PATH_LEN] = {};
char paths_close[MAX_FILES][MAX_PATH_LEN] = {};

int rets_stat[MAX_FILES] = {};
int rets_close[MAX_FILES] = {};

int called_stat = 0;
int called_close = 0;

char _license[] SEC("license") = "GPL";

#endif /* _D_PATH_COMMON_H */
