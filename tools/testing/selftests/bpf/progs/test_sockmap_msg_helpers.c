// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Cloudflare

#include <errno.h>
#include <stdbool.h>
#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} sock_map SEC(".maps");

int cork = 0;

bool pull = false;
bool push = false;
bool pop = false;

int pull_start = 0;
int pull_end = 0;

int push_start = 0;
int push_end = 0;

int pop_start = 0;
int pop_len = 0;

int err;
int size;

SEC("sk_msg")
int msg_helpers(struct sk_msg_md *msg)
{
	size = msg->size;

	if (cork)
		err = bpf_msg_cork_bytes(msg, cork);

	if (pull)
		err = bpf_msg_pull_data(msg, pull_start, pull_end, 0);

	if (push)
		err = bpf_msg_push_data(msg, push_start, push_end, 0);

	if (pop)
		err = bpf_msg_pop_data(msg, pop_start, pop_len, 0);

	return SK_PASS;
}

char _license[] SEC("license") = "GPL";
