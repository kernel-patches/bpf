// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

const volatile pid_t pid;
const volatile size_t n;

int my_array[1] SEC(".data.my_array");

int my_array_with_neighbor[1] SEC(".data.my_array_and_var");
int my_var_with_neighbor SEC(".data.my_array_and_var");

int my_non_array SEC(".data.my_non_array");

int sum = 0;

SEC("tp/syscalls/sys_enter_getpid")
int array_sum(void *ctx)
{
	if (pid != (bpf_get_current_pid_tgid() >> 32))
		return 0;

	sum = 0;

	for (size_t i = 0; i < n; ++i)
		sum += my_array[i];

	return 0;
}
