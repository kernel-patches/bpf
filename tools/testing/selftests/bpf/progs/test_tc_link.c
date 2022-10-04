// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Isovalent */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

__u32 run;

SEC("tc/ingress")
int tc_handler_in(struct __sk_buff *skb)
{
#ifdef ENABLE_ATOMICS_TESTS
	__sync_fetch_and_or(&run, 1);
#else
	run |= 1;
#endif
	return TC_NEXT;
}

SEC("tc/egress")
int tc_handler_eg(struct __sk_buff *skb)
{
#ifdef ENABLE_ATOMICS_TESTS
	__sync_fetch_and_or(&run, 2);
#else
	run |= 2;
#endif
	return TC_NEXT;
}

SEC("tc/egress")
int tc_handler_old(struct __sk_buff *skb)
{
#ifdef ENABLE_ATOMICS_TESTS
	__sync_fetch_and_or(&run, 4);
#else
	run |= 4;
#endif
	return TC_NEXT;
}
