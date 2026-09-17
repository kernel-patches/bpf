// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

bool prog1_called = false;
bool prog2_called = false;
bool prog3_called = false;

SEC("raw_tp/sys_enter")
int prog1(const void *ctx)
{
	prog1_called = true;
	return 0;
}

SEC("raw_tp/sys_enter")
int prog2(const void *ctx)
{
	prog2_called = true;
	return 0;
}

SEC("raw_tp/sys_enter")
int prog3(const void *ctx)
{
	prog3_called = true;
	return 0;
}

char _license[] SEC("license") = "GPL";
