// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Facebook */

#include <vmlinux.h>
#include <string.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "errno.h"

char _license[] SEC("license") = "GPL";

static __u64 test_cb(__u64 p)
{
	bpf_printk("Hello map %u\n", p);
	return 0;
}

volatile int cnt = 0;

SEC("xdp")
int test_task_work(struct xdp_md *xdp)
{
	bpf_task_work_schedule(test_cb);
	return XDP_PASS;
}
