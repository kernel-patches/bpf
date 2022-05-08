// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct { \
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE); \
	__uint(map_flags, BPF_F_NO_PREALLOC); \
	__type(key, int); \
	__type(value, __u32); \
} map_to_pin SEC(".maps");
