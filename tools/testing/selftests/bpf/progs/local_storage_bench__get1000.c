// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "local_storage_bench_helpers.h"

#define TASK_STORAGE_GET_FUNC_FIRST50(name, thous, hun) \
SEC("fentry/" SYS_PREFIX "sys_getpgid") \
int name(void *ctx) \
{ \
	struct task_struct *task = bpf_get_current_task_btf(); \
	TASK_STORAGE_GET10(thous, hun, 0); \
	TASK_STORAGE_GET10(thous, hun, 1); \
	TASK_STORAGE_GET10(thous, hun, 2); \
	TASK_STORAGE_GET10(thous, hun, 3); \
	TASK_STORAGE_GET10(thous, hun, 4); \
	return 0; \
}

#define TASK_STORAGE_GET_FUNC_LAST50(name, thous, hun) \
SEC("fentry/" SYS_PREFIX "sys_getpgid") \
int name(void *ctx) \
{ \
	struct task_struct *task = bpf_get_current_task_btf(); \
	TASK_STORAGE_GET10(thous, hun, 5); \
	TASK_STORAGE_GET10(thous, hun, 6); \
	TASK_STORAGE_GET10(thous, hun, 7); \
	TASK_STORAGE_GET10(thous, hun, 8); \
	TASK_STORAGE_GET10(thous, hun, 9); \
	return 0; \
}

#define TASK_STORAGE_GET_FUNC_100(name, thous, hun) \
	TASK_STORAGE_GET_FUNC_FIRST50(name ## _first, thous, hun); \
	TASK_STORAGE_GET_FUNC_FIRST50(name ##  _last, thous, hun);

long important_hits = 0;
long hits = 0;

/* Create maps local_storage_bench_pinned_{0000, .., 0999} */
PINNED_MAP1000(0);

TASK_STORAGE_GET_FUNC_100(do_map_get_000, 0, 0);
TASK_STORAGE_GET_FUNC_100(do_map_get_100, 0, 1);
TASK_STORAGE_GET_FUNC_100(do_map_get_200, 0, 2);
TASK_STORAGE_GET_FUNC_100(do_map_get_300, 0, 3);
TASK_STORAGE_GET_FUNC_100(do_map_get_400, 0, 4);
TASK_STORAGE_GET_FUNC_100(do_map_get_500, 0, 5);
TASK_STORAGE_GET_FUNC_100(do_map_get_600, 0, 6);
TASK_STORAGE_GET_FUNC_100(do_map_get_700, 0, 7);
TASK_STORAGE_GET_FUNC_100(do_map_get_800, 0, 8);
TASK_STORAGE_GET_FUNC_100(do_map_get_900, 0, 9);

char _license[] SEC("license") = "GPL";
