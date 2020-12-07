// SPDX-License-Identifier: GPL-2.0
/*
 * Check if we can migrate child sockets.
 *
 *   1. If reuse_md->migration is 0 (SYN packet),
 *        return SK_PASS without selecting a listener.
 *   2. If reuse_md->migration is not 0 (socket migration),
 *        select a listener (reuseport_map[migrate_map[cookie]])
 *
 * Author: Kuniyuki Iwashima <kuniyu@amazon.co.jp>
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define NULL ((void *)0)

struct bpf_map_def SEC("maps") reuseport_map = {
	.type = BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(__u64),
	.max_entries = 256,
};

struct bpf_map_def SEC("maps") migrate_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(int),
	.max_entries = 256,
};

SEC("sk_reuseport/migrate")
int prog_select_reuseport_migrate(struct sk_reuseport_md *reuse_md)
{
	int *key, flags = 0;
	__u64 cookie;

	if (!reuse_md->migration)
		return SK_PASS;

	cookie = bpf_get_socket_cookie(reuse_md->sk);

	key = bpf_map_lookup_elem(&migrate_map, &cookie);
	if (key == NULL)
		return SK_DROP;

	bpf_sk_select_reuseport(reuse_md, &reuseport_map, key, flags);

	return SK_PASS;
}

int _version SEC("version") = 1;
char _license[] SEC("license") = "GPL";
