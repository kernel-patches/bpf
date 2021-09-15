// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021. Huawei Technologies Co., Ltd */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/stddef.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct bpf_dummy_ops_state {
	int val;
};

struct bpf_dummy_ops {
	int (*init)(void);
};

int state_val = 0;
int init_ret = 0;

SEC("struct_ops/dummy_ops_init")
int BPF_PROG(dummy_ops_init, struct bpf_dummy_ops_state *state)
{
	if (state)
		state->val = state_val;
	return init_ret;
}

SEC(".struct_ops")
struct bpf_dummy_ops dummy = {
	.init = (void *)dummy_ops_init,
};

char _license[] SEC("license") = "GPL";
