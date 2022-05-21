// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

#include "local_storage_bench.h"

TASK_STORAGE_GET_LOOP_PROG(false);

char _license[] SEC("license") = "GPL";
