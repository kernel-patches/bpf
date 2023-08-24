// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, 4);
	__type(key, int);
	__type(value, int);
} sock_map SEC(".maps");

u64 skmsg_redir_flags = 0;
u32 skmsg_redir_key = 0;

SEC("sk_msg")
int prog_skmsg_verdict(struct sk_msg_md *msg)
{
	u64 flags = skmsg_redir_flags;
	int key = skmsg_redir_key;

	bpf_msg_redirect_map(msg, &sock_map, key, flags);
	return SK_PASS;
}

char _license[] SEC("license") = "GPL";
