// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Facebook
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

int calls = 0;
int alt_calls = 0;

SEC("cgroup_skb/egress")
int egress(struct __sk_buff *skb)
{
	__sync_fetch_and_add(&calls, 1);
	return 1;
}

SEC("cgroup_skb/egress")
int egress_alt(struct __sk_buff *skb)
{
	__sync_fetch_and_add(&alt_calls, 1);
	return 1;
}

SEC("cgroup/sendmsg4")
int sendmsg4(struct bpf_sock_addr *ctx)
{
	return 1;
}

SEC("cgroup/sendmsg6")
int sendmsg6(struct bpf_sock_addr *ctx)
{
	ctx->msg_src_ip6[2] = 0;
	return 1;
}

char _license[] SEC("license") = "GPL";
