// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 KylinSoft */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} sock_map SEC(".maps");

/* Self-redirect: the backlog work keeps re-sending the skb. */
SEC("sk_skb/verdict")
int redir_to_self(struct __sk_buff *skb)
{
	return bpf_sk_redirect_map(skb, &sock_map, 0, 0);
}

char _license[] SEC("license") = "GPL";
