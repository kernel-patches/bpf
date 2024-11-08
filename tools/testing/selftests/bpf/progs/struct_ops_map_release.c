// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2024 Huawei Technologies Co., Ltd */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "../bpf_testmod/bpf_testmod.h"
#include "../bpf_testmod/bpf_testmod_kfunc.h"

char _license[] SEC("license") = "GPL";

SEC("struct_ops.s/test_1")
int BPF_PROG(test_1_prog)
{
	bpf_kfunc_msleep(100);
	return 0;
}

SEC("struct_ops/test_2")
int BPF_PROG(test_2_prog, int a, int b)
{
	return 0;
}

SEC(".struct_ops")
struct bpf_testmod_ops testmod_ops = {
	.test_1 = (void *)test_1_prog,
	.test_2 = (void *)test_2_prog
};
