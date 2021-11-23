// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

struct callback_ctx {
	int output;
};

/* These should be set by the user program */
u32 nested_callback_nr_loops;
u32 stop_index = -1;
u32 nr_loops;

/* Making these global variables so that the userspace program
 * can verify the output through the skeleton
 */
int nr_loops_returned;
int g_output;
int err;

static int callback(__u32 index, void *data)
{
	struct callback_ctx *ctx = data;

	if (index >= stop_index)
		return 1;

	ctx->output += index;

	return 0;
}

static int empty_callback(__u32 index, void *data)
{
	return 0;
}

static int nested_callback2(__u32 index, void *data)
{
	nr_loops_returned += bpf_loop(nested_callback_nr_loops, callback, data, 0);

	return 0;
}

static int nested_callback1(__u32 index, void *data)
{
	bpf_loop(nested_callback_nr_loops, nested_callback2, data, 0);
	return 0;
}

SEC("tc")
int test_prog(struct __sk_buff *skb)
{
	struct callback_ctx data = {};

	nr_loops_returned = bpf_loop(nr_loops, callback, &data, 0);

	if (nr_loops_returned < 0)
		err = nr_loops_returned;
	else
		g_output = data.output;

	return 0;
}

SEC("tc")
int prog_null_ctx(struct __sk_buff *skb)
{
	nr_loops_returned = bpf_loop(nr_loops, empty_callback, NULL, 0);

	return 0;
}

SEC("tc")
int prog_invalid_flags(struct __sk_buff *skb)
{
	struct callback_ctx data = {};

	err = bpf_loop(nr_loops, callback, &data, 1);

	return 0;
}

SEC("tc")
int prog_nested_calls(struct __sk_buff *skb)
{
	struct callback_ctx data = {};

	nr_loops_returned = 0;
	bpf_loop(nr_loops, nested_callback1, &data, 0);

	g_output = data.output;

	return 0;
}
