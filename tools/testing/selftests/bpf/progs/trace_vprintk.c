// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

int trace_vprintk_ret = 0;
int trace_vprintk_ran = 0;

SEC("fentry/__x64_sys_nanosleep")
int sys_enter(void *ctx)
{
	static const char one[] = "1";
	static const char three[] = "3";
	static const char five[] = "5";
	static const char seven[] = "7";
	static const char nine[] = "9";

	trace_vprintk_ret = __bpf_vprintk("%s,%d,%s,%d,%s,%d,%s,%d,%s,%d %d\n",
		one, 2, three, 4, five, 6, seven, 8, nine, 10, ++trace_vprintk_ran);
	return 0;
}
