// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Facebook */
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "cgroup_tcp_skb.h"

char _license[] SEC("license") = "GPL";

__u16 g_sock_port = 0;
__u32 g_sock_state = 0;
int g_unexpected = 0;

int needed_tcp_pkt(struct __sk_buff *skb, struct tcphdr *tcph)
{
	struct ipv6hdr ip6h;

	if (skb->protocol != bpf_htons(ETH_P_IPV6))
		return 0;
	if (bpf_skb_load_bytes(skb, 0, &ip6h, sizeof(ip6h)))
		return 0;

	if (ip6h.nexthdr != IPPROTO_TCP)
		return 0;

	if (bpf_skb_load_bytes(skb, sizeof(ip6h), tcph, sizeof(*tcph)))
		return 0;

	if (tcph->source != bpf_htons(g_sock_port) &&
	    tcph->dest != bpf_htons(g_sock_port))
		return 0;

	return 1;
}

/* Run accept() on a socket in the cgroup to receive a new connection. */
#define EGRESS_ACCEPT							\
	case SYN_RECV_SENDING_SYN_ACK:					\
		if (tcph.fin || !tcph.syn || tcph.rst || !tcph.ack)	\
			g_unexpected++;					\
		else							\
			g_sock_state = SYN_RECV;			\
		break

#define INGRESS_ACCEPT							\
	case INIT:							\
		if (!tcph.syn || tcph.fin || tcph.rst || tcph.ack)	\
			g_unexpected++;					\
		else							\
			g_sock_state = SYN_RECV_SENDING_SYN_ACK;	\
		break;							\
	case SYN_RECV:							\
		if (tcph.fin || tcph.syn || tcph.rst || !tcph.ack)	\
			g_unexpected++;					\
		else							\
			g_sock_state = ESTABLISHED;			\
		break

/* Run connect() on a socket in the cgroup to start a new connection. */
#define EGRESS_CONNECT							\
	case INIT:							\
		if (!tcph.syn || tcph.fin || tcph.rst || tcph.ack)	\
			g_unexpected++;					\
		else							\
			g_sock_state = SYN_SENT;			\
		break

#define INGRESS_CONNECT							\
	case SYN_SENT:							\
		if (tcph.fin || !tcph.syn || tcph.rst || !tcph.ack)	\
			g_unexpected++;					\
		else							\
			g_sock_state = ESTABLISHED;			\
		break

/* The connection is closed by the peer outside the cgroup. */
#define EGRESS_CLOSE_REMOTE						\
	case ESTABLISHED:						\
		break;							\
	case CLOSE_WAIT_SENDING_ACK:					\
		if (tcph.fin || tcph.syn || tcph.rst || !tcph.ack)	\
			g_unexpected++;					\
		else							\
			g_sock_state = CLOSE_WAIT;			\
		break;							\
	case CLOSE_WAIT:						\
		if (!tcph.fin)						\
			g_unexpected++;					\
		else							\
			g_sock_state = LAST_ACK;			\
		break

#define INGRESS_CLOSE_REMOTE						\
	case ESTABLISHED:						\
		if (tcph.fin)						\
			g_sock_state = CLOSE_WAIT_SENDING_ACK;		\
		break;							\
	case LAST_ACK:							\
		if (tcph.fin || tcph.syn || tcph.rst || !tcph.ack)	\
			g_unexpected++;					\
		else							\
			g_sock_state = CLOSED;				\
		break

/* The connection is closed by the endpoint inside the cgroup. */
#define EGRESS_CLOSE_LOCAL						\
	case ESTABLISHED:						\
		if (tcph.fin)						\
			g_sock_state = FIN_WAIT1;			\
		break;							\
	case TIME_WAIT_SENDING_ACK:					\
		if (tcph.fin || tcph.syn || tcph.rst || !tcph.ack)	\
			g_unexpected++;					\
		else							\
			g_sock_state = TIME_WAIT;			\
		break

#define INGRESS_CLOSE_LOCAL						\
	case ESTABLISHED:						\
		break;							\
	case FIN_WAIT1:							\
		if (tcph.fin || tcph.syn || tcph.rst || !tcph.ack)	\
			g_unexpected++;					\
		else							\
			g_sock_state = FIN_WAIT2;			\
		break;							\
	case FIN_WAIT2:							\
		if (!tcph.fin || tcph.syn || tcph.rst || !tcph.ack)	\
			g_unexpected++;					\
		else							\
			g_sock_state = TIME_WAIT_SENDING_ACK;		\
		break

/* Check the types of outgoing packets of a server socket to make sure they
 * are consistent with the state of the server socket.
 *
 * The connection is closed by the client side.
 */
SEC("cgroup_skb/egress")
int server_egress(struct __sk_buff *skb)
{
	struct tcphdr tcph;

	if (!needed_tcp_pkt(skb, &tcph))
		return 1;

	/* Egress of the server socket. */
	switch (g_sock_state) {
	EGRESS_ACCEPT;
	EGRESS_CLOSE_REMOTE;
	default:
		g_unexpected++;
		break;
	}
	return 1;
}

/* Check the types of incoming packets of a server socket to make sure they
 * are consistent with the state of the server socket.
 *
 * The connection is closed by the client side.
 */
SEC("cgroup_skb/ingress")
int server_ingress(struct __sk_buff *skb)
{
	struct tcphdr tcph;

	if (!needed_tcp_pkt(skb, &tcph))
		return 1;

	/* Ingress of the server socket. */
	switch (g_sock_state) {
	INGRESS_ACCEPT;
	INGRESS_CLOSE_REMOTE;
	default:
		g_unexpected++;
		break;
	}
	return 1;
}


/* Check the types of outgoing packets of a server socket to make sure they
 * are consistent with the state of the server socket.
 *
 * The connection is closed by the server side.
 */
SEC("cgroup_skb/egress")
int server_egress_srv(struct __sk_buff *skb)
{
	struct tcphdr tcph;

	if (!needed_tcp_pkt(skb, &tcph))
		return 1;

	/* Egress of the server socket. */
	switch (g_sock_state) {
	EGRESS_ACCEPT;
	EGRESS_CLOSE_LOCAL;
	default:
		g_unexpected++;
		break;
	}
	return 1;
}

/* Check the types of incoming packets of a server socket to make sure they
 * are consistent with the state of the server socket.
 *
 * The connection is closed by the server side.
 */
SEC("cgroup_skb/ingress")
int server_ingress_srv(struct __sk_buff *skb)
{
	struct tcphdr tcph;

	if (!needed_tcp_pkt(skb, &tcph))
		return 1;

	/* Ingress of the server socket. */
	switch (g_sock_state) {
	INGRESS_ACCEPT;
	INGRESS_CLOSE_LOCAL;
	default:
		g_unexpected++;
		break;
	}
	return 1;
}


/* Check the types of outgoing packets of a client socket to make sure they
 * are consistent with the state of the client socket.
 *
 * The connection is closed by the server side.
 */
SEC("cgroup_skb/egress")
int client_egress_srv(struct __sk_buff *skb)
{
	struct tcphdr tcph;

	if (!needed_tcp_pkt(skb, &tcph))
		return 1;

	/* Egress of the server socket. */
	switch (g_sock_state) {
	EGRESS_CONNECT;
	EGRESS_CLOSE_REMOTE;
	default:
		g_unexpected++;
		break;
	}
	return 1;
}

/* Check the types of incoming packets of a client socket to make sure they
 * are consistent with the state of the client socket.
 *
 * The connection is closed by the server side.
 */
SEC("cgroup_skb/ingress")
int client_ingress_srv(struct __sk_buff *skb)
{
	struct tcphdr tcph;

	if (!needed_tcp_pkt(skb, &tcph))
		return 1;

	/* Ingress of the server socket. */
	switch (g_sock_state) {
	INGRESS_CONNECT;
	INGRESS_CLOSE_REMOTE;
	default:
		g_unexpected++;
		break;
	}
	return 1;
}


/* Check the types of outgoing packets of a client socket to make sure they
 * are consistent with the state of the client socket.
 *
 * The connection is closed by the client side.
 */
SEC("cgroup_skb/egress")
int client_egress(struct __sk_buff *skb)
{
	struct tcphdr tcph;

	if (!needed_tcp_pkt(skb, &tcph))
		return 1;

	/* Egress of the server socket. */
	switch (g_sock_state) {
	EGRESS_CONNECT;
	EGRESS_CLOSE_LOCAL;
	default:
		g_unexpected++;
		break;
	}
	return 1;
}

/* Check the types of incoming packets of a client socket to make sure they
 * are consistent with the state of the client socket.
 *
 * The connection is closed by the client side.
 */
SEC("cgroup_skb/ingress")
int client_ingress(struct __sk_buff *skb)
{
	struct tcphdr tcph;

	if (!needed_tcp_pkt(skb, &tcph))
		return 1;

	/* Ingress of the server socket. */
	switch (g_sock_state) {
	INGRESS_CONNECT;
	INGRESS_CLOSE_LOCAL;
	default:
		g_unexpected++;
		break;
	}
	return 1;
}



