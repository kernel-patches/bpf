// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Isovalent */
#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>
#include "bpf_misc.h"

#define NR_EXCHANGES 18

char LICENSE[] SEC("license") = "GPL";

__u64 sk_cookie_seen;
__u64 reuseport_executed;
union {
	struct tcphdr tcp;
	struct udphdr udp;
} headers;

const volatile __u16 dest_port;
const volatile bool select_sock;
const volatile bool classic_action;
const volatile bool redirect_action;
const volatile bool pass_observer;
const volatile bool check_redirect;
const volatile bool drop_after_assign;
__u64 assign_calls;
__u64 assign_errors;
__u64 redirected_packets;
__u64 redirected_sockets;
__u64 completed_packets;

struct {
	__u64 expected_cookie;
	__u64 sk_cookie;
	__u64 reuse_calls;
	__u32 assign_calls;
	__u32 assign_errors;
	__u32 select_errors;
	__u32 cookie_errors;
	__u32 index;
	__u32 drop;
	__u16 source_port;
} exchanges[NR_EXCHANGES];

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} sk_map SEC(".maps");

static __always_inline typeof(exchanges[0]) *find_exchange(__u16 source)
{
	int i;

#pragma unroll
	for (i = 0; i < ARRAY_SIZE(exchanges); i++) {
		if (source && exchanges[i].source_port == source)
			return &exchanges[i];
	}
	return NULL;
}

static __always_inline int select_exchange(struct sk_reuseport_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	typeof(exchanges[0]) *exchange;
	struct tcphdr *th = data;
	struct udphdr *uh = data;
	__u64 increment = 1;
	int ret = SK_DROP;
	__u16 source;
	__u64 cookie;
	__u32 index;

	if (ctx->ip_protocol == IPPROTO_TCP) {
		if ((void *)(th + 1) > data_end || !th->syn || th->ack ||
		    th->dest != bpf_htons(dest_port))
			return SK_DROP;
		source = th->source;
	} else if (ctx->ip_protocol == IPPROTO_UDP) {
		if ((void *)(uh + 1) > data_end ||
		    uh->dest != bpf_htons(dest_port))
			return SK_DROP;
		source = uh->source;
	} else {
		return SK_DROP;
	}
	exchange = find_exchange(source);
	if (!exchange)
		return SK_DROP;
	cookie = bpf_get_socket_cookie(ctx->sk);
	exchange->sk_cookie = cookie;
	if (cookie != exchange->expected_cookie)
		__sync_fetch_and_add(&exchange->cookie_errors, 1);
	if (!exchange->drop) {
		index = exchange->index;
		if (bpf_sk_select_reuseport(ctx, &sk_map, &index, 0))
			__sync_fetch_and_add(&exchange->select_errors, 1);
		else
			ret = SK_PASS;
	}
	asm volatile("%0 = atomic_fetch_add((u64 *)(%1 + 0), %0);"
		     : "+r"(increment) : "r"(&exchange->reuse_calls) : "memory");
	return ret;
}

SEC("sk_reuseport")
int reuse_accept(struct sk_reuseport_md *ctx)
{
	if (select_sock)
		return select_exchange(ctx);
	reuseport_executed++;

	if (ctx->ip_protocol == IPPROTO_TCP) {
		if (ctx->data + sizeof(headers.tcp) > ctx->data_end)
			return SK_DROP;

		if (__builtin_memcmp(&headers.tcp, ctx->data, sizeof(headers.tcp)) != 0)
			return SK_DROP;
	} else if (ctx->ip_protocol == IPPROTO_UDP) {
		if (ctx->data + sizeof(headers.udp) > ctx->data_end)
			return SK_DROP;

		if (__builtin_memcmp(&headers.udp, ctx->data, sizeof(headers.udp)) != 0)
			return SK_DROP;
	} else {
		return SK_DROP;
	}

	sk_cookie_seen = bpf_get_socket_cookie(ctx->sk);
	return SK_PASS;
}

SEC("sk_reuseport")
int reuse_drop(struct sk_reuseport_md *ctx)
{
	if (select_sock)
		return select_exchange(ctx);
	reuseport_executed++;
	sk_cookie_seen = 0;
	return SK_DROP;
}

static int
assign_sk(struct __sk_buff *skb, typeof(exchanges[0]) *exchange)
{
	struct bpf_sock *sk;
	int zero = 0, ret;

	sk = bpf_map_lookup_elem(&sk_map, &zero);
	if (!sk)
		return TC_ACT_SHOT;
	ret = bpf_sk_assign(skb, sk, 0);
	if (select_sock) {
		__sync_fetch_and_add(&exchange->assign_calls, 1);
		if (ret)
			__sync_fetch_and_add(&exchange->assign_errors, 1);
	} else {
		__sync_fetch_and_add(&assign_calls, 1);
		if (ret)
			__sync_fetch_and_add(&assign_errors, 1);
	}
	bpf_sk_release(sk);
	if (ret)
		return TC_ACT_SHOT;
	if (classic_action) {
		skb->mark = 1;
		if (redirect_action)
			return bpf_redirect(skb->ifindex, BPF_F_INGRESS);
		return TC_ACT_PIPE;
	}
	if (check_redirect) {
		if (drop_after_assign) {
			__sync_lock_test_and_set(&completed_packets, assign_calls);
			return TC_ACT_SHOT;
		}
		skb->mark = 1;
		return bpf_redirect(skb->ifindex, BPF_F_INGRESS);
	}
	if (select_sock)
		return bpf_redirect(skb->ifindex, BPF_F_INGRESS);
	return TC_ACT_OK;
}

static int
maybe_assign_tcp(struct __sk_buff *skb, struct tcphdr *th)
{
	typeof(exchanges[0]) *exchange = NULL;

	if (th + 1 > (void *)(long)(skb->data_end))
		return TC_ACT_SHOT;

	if (!th->syn || th->ack || th->dest != bpf_htons(dest_port))
		return TC_ACT_OK;

	if (select_sock) {
		exchange = find_exchange(th->source);
		if (!exchange)
			return TC_ACT_OK;
	} else {
		__builtin_memcpy(&headers.tcp, th, sizeof(headers.tcp));
	}
	return assign_sk(skb, exchange);
}

static int
maybe_assign_udp(struct __sk_buff *skb, struct udphdr *uh)
{
	typeof(exchanges[0]) *exchange = NULL;

	if (uh + 1 > (void *)(long)(skb->data_end))
		return TC_ACT_SHOT;

	if (uh->dest != bpf_htons(dest_port))
		return TC_ACT_OK;

	if (select_sock) {
		exchange = find_exchange(uh->source);
		if (!exchange)
			return TC_ACT_OK;
	} else {
		__builtin_memcpy(&headers.udp, uh, sizeof(headers.udp));
	}
	return assign_sk(skb, exchange);
}

static __always_inline int process_packet(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct ethhdr *eth;

	if (check_redirect && skb->mark == 1) {
		__sync_fetch_and_add(&redirected_packets, 1);
		if (skb->sk)
			__sync_fetch_and_add(&redirected_sockets, 1);
		__sync_lock_test_and_set(&completed_packets, redirected_packets);
		return pass_observer ? TC_ACT_OK : TC_ACT_SHOT;
	}

	eth = (struct ethhdr *)(data);
	if (eth + 1 > data_end)
		return TC_ACT_SHOT;

	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = (struct iphdr *)(data + sizeof(*eth));

		if (iph + 1 > data_end)
			return TC_ACT_SHOT;

		if (iph->protocol == IPPROTO_TCP)
			return maybe_assign_tcp(skb, (struct tcphdr *)(iph + 1));
		else if (iph->protocol == IPPROTO_UDP)
			return maybe_assign_udp(skb, (struct udphdr *)(iph + 1));
		else
			return TC_ACT_SHOT;
	} else {
		struct ipv6hdr *ip6h = (struct ipv6hdr *)(data + sizeof(*eth));

		if (ip6h + 1 > data_end)
			return TC_ACT_SHOT;

		if (ip6h->nexthdr == IPPROTO_TCP)
			return maybe_assign_tcp(skb, (struct tcphdr *)(ip6h + 1));
		else if (ip6h->nexthdr == IPPROTO_UDP)
			return maybe_assign_udp(skb, (struct udphdr *)(ip6h + 1));
		else
			return TC_ACT_SHOT;
	}
}

SEC("tc")
int tc_main(struct __sk_buff *skb)
{
	return process_packet(skb);
}

SEC("action")
int action_assign(struct __sk_buff *skb)
{
	return process_packet(skb);
}
