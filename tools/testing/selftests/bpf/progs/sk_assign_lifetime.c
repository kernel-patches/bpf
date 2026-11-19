// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct nf_queue_entry___local {
	struct sk_buff *skb;
} __attribute__((preserve_access_index));

struct queue_state {
	__u64 destructor;
	__u64 sk;
	__u32 refs;
	__u32 mark;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);
	__type(value, struct queue_state);
} queued SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u32);
} observed SEC(".maps");

struct release_state {
	__u64 parent;
	__u64 sk;
	__u64 puts;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8);
	__type(key, __u64);
	__type(value, struct release_state);
} releasing SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8);
	__type(key, __u64);
	__type(value, __u64);
} active_releases SEC(".maps");

const volatile __u64 listener_cookie;
const volatile __u64 release_cookie;
__u64 released_packets;
__u64 release_errors;
__u64 queue_errors;

static __always_inline bool is_test_listener(struct sock *sk)
{
	return sk && listener_cookie &&
	       BPF_CORE_READ(sk, __sk_common.skc_state) == BPF_TCP_LISTEN &&
	       BPF_CORE_READ(sk, __sk_common.skc_cookie.counter) == listener_cookie;
}

SEC("fentry/nf_queue")
int BPF_PROG(queue_enter, struct sk_buff *skb)
{
	struct sock *sk = BPF_CORE_READ(skb, sk);
	struct queue_state state = {};
	__u64 key = (__u64)skb;

	if (!is_test_listener(sk))
		return 0;
	state.refs = BPF_CORE_READ(sk, __sk_common.skc_refcnt.refs.counter);
	state.sk = (__u64)sk;
	state.destructor = (__u64)BPF_CORE_READ(skb, destructor);
	state.mark = BPF_CORE_READ(skb, mark);
	if (bpf_map_update_elem(&queued, &key, &state, BPF_NOEXIST))
		__sync_fetch_and_add(&queue_errors, 1);
	return 0;
}

SEC("fentry/nfqnl_enqueue_packet")
int BPF_PROG(queue_observe, struct nf_queue_entry___local *entry,
	     unsigned int queuenum)
{
	struct sk_buff *skb = BPF_CORE_READ(entry, skb);
	struct queue_state *before;
	__u64 key = (__u64)skb;
	__u32 mark, errors;
	struct sock *sk;
	__u32 refs;

	sk = BPF_CORE_READ(skb, sk);
	if (!is_test_listener(sk))
		return 0;
	before = bpf_map_lookup_elem(&queued, &key);
	if (!before)
		return 0;
	refs = BPF_CORE_READ(sk, __sk_common.skc_refcnt.refs.counter);
	mark = BPF_CORE_READ(skb, mark);
	errors = before->refs < 2 || refs < 2 ||
		 (__u64)sk != before->sk || mark != before->mark ||
		 (__u64)BPF_CORE_READ(skb, destructor) != before->destructor;
	if (bpf_map_update_elem(&observed, &mark, &errors, BPF_NOEXIST))
		__sync_fetch_and_add(&queue_errors, 1);
	bpf_map_delete_elem(&queued, &key);
	return 0;
}

SEC("fentry/sock_pfree_ref")
int BPF_PROG(release_enter, struct sk_buff *skb)
{
	struct sock *sk = BPF_CORE_READ(skb, sk);
	__u64 task = bpf_get_current_task();
	struct release_state state = {};
	__u64 key = (__u64)skb;
	__u64 *parent;

	if (!sk || !release_cookie ||
	    BPF_CORE_READ(sk, __sk_common.skc_cookie.counter) != release_cookie)
		return 0;
	parent = bpf_map_lookup_elem(&active_releases, &task);
	if (parent)
		state.parent = *parent;
	state.sk = (__u64)sk;
	if (bpf_map_update_elem(&releasing, &key, &state, BPF_NOEXIST)) {
		__sync_fetch_and_add(&release_errors, 1);
		return 0;
	}
	if (bpf_map_update_elem(&active_releases, &task, &key, BPF_ANY)) {
		__sync_fetch_and_add(&release_errors, 1);
		bpf_map_delete_elem(&releasing, &key);
	}
	return 0;
}

SEC("fentry/sock_gen_put")
int BPF_PROG(release_put, struct sock *sk)
{
	__u64 task = bpf_get_current_task();
	struct release_state *state;
	__u64 *key;

	key = bpf_map_lookup_elem(&active_releases, &task);
	if (!key)
		return 0;
	state = bpf_map_lookup_elem(&releasing, key);
	if (state && state->sk == (__u64)sk)
		state->puts++;
	return 0;
}

SEC("fexit/sock_pfree_ref")
int BPF_PROG(release_exit, struct sk_buff *skb)
{
	__u64 task = bpf_get_current_task();
	struct release_state *before;
	__u64 key = (__u64)skb;
	__u64 increment = 1;
	int ret;

	before = bpf_map_lookup_elem(&releasing, &key);
	if (!before)
		return 0;
	if (before->puts != 1)
		__sync_fetch_and_add(&release_errors, 1);
	if (before->parent)
		ret = bpf_map_update_elem(&active_releases, &task,
					  &before->parent, BPF_EXIST);
	else
		ret = bpf_map_delete_elem(&active_releases, &task);
	if (ret)
		__sync_fetch_and_add(&release_errors, 1);
	if (bpf_map_delete_elem(&releasing, &key))
		__sync_fetch_and_add(&release_errors, 1);
	asm volatile("%0 = atomic_fetch_add((u64 *)(%1 + 0), %0);"
		     : "+r"(increment) : "r"(&released_packets) : "memory");
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
