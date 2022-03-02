// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

const int rovar1;
int out1;

extern int lib_routine(void);

SEC("raw_tp/sys_enter")
int handler1(const void *ctx)
{
	out1 = lib_routine() * rovar1;
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
int VERSION SEC("version") = 1;
