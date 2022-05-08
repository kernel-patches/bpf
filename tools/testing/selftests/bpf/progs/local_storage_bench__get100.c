// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "local_storage_bench_helpers.h"

long important_hits = 0;
long hits = 0;

/* Create maps local_storage_bench_pinned_{0000, .., 0099} */
PINNED_MAP100(0, 0);

SEC("fentry/" SYS_PREFIX "sys_getpgid")
int do_map_get(void *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();

	TASK_STORAGE_GET10(0, 0, 0);
	TASK_STORAGE_GET10(0, 0, 1);
	TASK_STORAGE_GET10(0, 0, 2);
	TASK_STORAGE_GET10(0, 0, 3);
	TASK_STORAGE_GET10(0, 0, 4);
	return 0;
}

/* Need to access maps in diff progs to work around verifier MAX_USED_MAPS */
SEC("fentry/" SYS_PREFIX "sys_getpgid")
int do_map_get2(void *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();

	TASK_STORAGE_GET10(0, 0, 5);
	TASK_STORAGE_GET10(0, 0, 6);
	TASK_STORAGE_GET10(0, 0, 7);
	TASK_STORAGE_GET10(0, 0, 8);
	TASK_STORAGE_GET10(0, 0, 9);
	return 0;
}

char _license[] SEC("license") = "GPL";
