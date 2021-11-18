// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

struct callback_ctx {
	int output;
};

/* This should be set by the user program */
u32 nr_iterations;
u32 stop_index = -1;

/* Making these global variables so that the userspace program
 * can verify the output through the skeleton
 */
int nr_iterations_completed;
int g_output;
int err;

static int callback_fn(__u32 index, void *data)
{
	struct callback_ctx *ctx = data;

	if (index >= stop_index)
		return 1;

	ctx->output += index;

	return 0;
}

static int empty_callback_fn(__u32 index, void *data)
{
	return 0;
}

SEC("tc")
int test_prog(struct __sk_buff *skb)
{
	struct callback_ctx data = {};

	nr_iterations_completed = bpf_for_each(nr_iterations, callback_fn, &data, 0);

	g_output = data.output;

	return 0;
}

SEC("tc")
int prog_null_ctx(struct __sk_buff *skb)
{
	nr_iterations_completed = bpf_for_each(nr_iterations, empty_callback_fn, NULL, 0);

	return 0;
}

SEC("tc")
int prog_invalid_flags(struct __sk_buff *skb)
{
	struct callback_ctx data = {};

	err = bpf_for_each(nr_iterations, callback_fn, &data, 1);

	return 0;
}
