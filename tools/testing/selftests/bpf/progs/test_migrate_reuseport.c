// SPDX-License-Identifier: GPL-2.0
/*
 * Check if we can migrate child sockets.
 *
 *   1. If reuse_md->migrating_sk is NULL (SYN packet),
 *        return SK_PASS without selecting a listener.
 *   2. If reuse_md->migrating_sk is not NULL (socket migration),
 *        select a listener (reuseport_map[migrate_map[cookie]])
 *
 * Author: Kuniyuki Iwashima <kuniyu@amazon.co.jp>
 */

#include <stddef.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
	__uint(max_entries, 256);
	__type(key, int);
	__type(value, __u64);
} reuseport_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u64);
	__type(value, int);
} migrate_map SEC(".maps");

int migrated_at_close SEC(".data");
int migrated_at_send_synack SEC(".data");
int migrated_at_recv_ack SEC(".data");

SEC("sk_reuseport/migrate")
int prog_migrate_reuseport(struct sk_reuseport_md *reuse_md)
{
	int *key, flags = 0, state, err;
	__u64 cookie;

	if (!reuse_md->migrating_sk)
		return SK_PASS;

	state = reuse_md->migrating_sk->state;
	cookie = bpf_get_socket_cookie(reuse_md->sk);

	key = bpf_map_lookup_elem(&migrate_map, &cookie);
	if (!key)
		return SK_DROP;

	err = bpf_sk_select_reuseport(reuse_md, &reuseport_map, key, flags);
	if (err)
		return SK_PASS;

	if (state == BPF_TCP_ESTABLISHED || state == BPF_TCP_SYN_RECV) {
		migrated_at_close++;
	} else if (BPF_TCP_NEW_SYN_RECV) {
		if (!reuse_md->len)
			migrated_at_send_synack++;
		else
			migrated_at_recv_ack++;
	}

	return SK_PASS;
}

char _license[] SEC("license") = "GPL";
