// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 ThisSeanZhang */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP_TEST		0x0800
#define ETH_P_IPV6_TEST		0x86dd
#define ETH_P_PPP_SES_TEST	0x8864
#define PPP_IP_TEST		0x21
#define PPP_IPV6_TEST		0x57

#define ETH_HLEN_TEST		14
#define PPPOE_SES_HLEN_TEST	8

#define TC_ACT_OK_TEST		0
#define TC_ACT_SHOT_TEST	2

/* Selects the bpf_skb_adjust_room() call made by tc_pppoe_reject. */
int reject_case;

/* skb->protocol as observed after the helper call. */
int encap_proto;
int decap_proto;

/*
 * Set when tc_pppoe_reject observes a call that should have been
 * rejected by the helper.
 */
int reject_unexpected;

SEC("tc")
int tc_pppoe_encap(struct __sk_buff *skb)
{
	__u8 hdr[PPPOE_SES_HLEN_TEST] = {
		0x11, 0x00,			/* ver, type, code */
		0xde, 0xad,			/* session id */
		0x00, 0x00,			/* length, set below */
		0x00, 0x00,			/* PPP protocol, set below */
	};
	struct ethhdr eth;
	/*
	 * The PPPoE length field covers everything after the 6 byte
	 * session header: the PPP protocol field plus the payload.
	 */
	__u16 plen = skb->len - ETH_HLEN_TEST + 2;

	hdr[4] = (plen >> 8) & 0xff;
	hdr[5] = plen & 0xff;

	switch (skb->protocol) {
	case bpf_htons(ETH_P_IP_TEST):
		hdr[7] = PPP_IP_TEST;
		break;
	case bpf_htons(ETH_P_IPV6_TEST):
		hdr[7] = PPP_IPV6_TEST;
		break;
	default:
		return TC_ACT_SHOT_TEST;
	}

	if (bpf_skb_adjust_room(skb, PPPOE_SES_HLEN_TEST, BPF_ADJ_ROOM_MAC,
				BPF_F_ADJ_ROOM_ENCAP_PPPOE))
		return TC_ACT_SHOT_TEST;

	encap_proto = skb->protocol;

	if (bpf_skb_store_bytes(skb, ETH_HLEN_TEST, hdr, sizeof(hdr), 0))
		return TC_ACT_SHOT_TEST;

	if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)))
		return TC_ACT_SHOT_TEST;
	eth.h_proto = bpf_htons(ETH_P_PPP_SES_TEST);
	if (bpf_skb_store_bytes(skb, 0, &eth, sizeof(eth), 0))
		return TC_ACT_SHOT_TEST;

	return TC_ACT_OK_TEST;
}

SEC("tc")
int tc_pppoe_decap(struct __sk_buff *skb)
{
	struct ethhdr eth;

	if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)))
		return TC_ACT_SHOT_TEST;
	if (eth.h_proto != bpf_htons(ETH_P_PPP_SES_TEST))
		return TC_ACT_SHOT_TEST;

	if (bpf_skb_adjust_room(skb, -PPPOE_SES_HLEN_TEST, BPF_ADJ_ROOM_MAC,
				BPF_F_ADJ_ROOM_DECAP_PPPOE))
		return TC_ACT_SHOT_TEST;

	decap_proto = skb->protocol;

	/*
	 * Restore the ethertype to the protocol of the decapsulated
	 * payload, as picked by the kernel from the PPP protocol field.
	 */
	eth.h_proto = (__be16)skb->protocol;
	if (bpf_skb_store_bytes(skb, 0, &eth, sizeof(eth), 0))
		return TC_ACT_SHOT_TEST;

	return TC_ACT_OK_TEST;
}

/*
 * Every bpf_skb_adjust_room() call below must be rejected by the
 * helper; tc_pppoe_reject reports (and fails the test) if one of
 * them unexpectedly succeeds.
 */
SEC("tc")
int tc_pppoe_reject(struct __sk_buff *skb)
{
	int ret = 0;

	switch (reject_case) {
	case 1:
		/* Encap with a wrong room size. */
		ret = bpf_skb_adjust_room(skb, PPPOE_SES_HLEN_TEST - 4,
					  BPF_ADJ_ROOM_MAC,
					  BPF_F_ADJ_ROOM_ENCAP_PPPOE);
		break;
	case 2:
		/* Encap at the wrong position. */
		ret = bpf_skb_adjust_room(skb, PPPOE_SES_HLEN_TEST,
					  BPF_ADJ_ROOM_NET,
					  BPF_F_ADJ_ROOM_ENCAP_PPPOE);
		break;
	case 3:
		/* Encap with a negative room size. */
		ret = bpf_skb_adjust_room(skb, -PPPOE_SES_HLEN_TEST,
					  BPF_ADJ_ROOM_MAC,
					  BPF_F_ADJ_ROOM_ENCAP_PPPOE);
		break;
	case 4:
		/* Encap flag combined with a decap flag. */
		ret = bpf_skb_adjust_room(skb, PPPOE_SES_HLEN_TEST,
					  BPF_ADJ_ROOM_MAC,
					  BPF_F_ADJ_ROOM_ENCAP_PPPOE |
					  BPF_F_ADJ_ROOM_DECAP_PPPOE);
		break;
	case 5:
		/* Shrink of a PPPoE packet without the PPPoE flag. */
		ret = bpf_skb_adjust_room(skb, -PPPOE_SES_HLEN_TEST,
					  BPF_ADJ_ROOM_MAC, 0);
		break;
	case 6:
		/* Decap of a non-PPPoE packet (plain IP or fake PPP proto). */
		ret = bpf_skb_adjust_room(skb, -PPPOE_SES_HLEN_TEST,
					  BPF_ADJ_ROOM_MAC,
					  BPF_F_ADJ_ROOM_DECAP_PPPOE);
		break;
	}

	if (!ret)
		reject_unexpected = 1;

	return TC_ACT_SHOT_TEST;
}

char _license[] SEC("license") = "GPL";
