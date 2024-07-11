// SPDX-License-Identifier: GPL-2.0
/*
 * Author:
 *	Juntong Deng <juntong.deng@outlook.com>
 */

#ifndef __TEST_DUMP_ALL_SOCKET_H
#define __TEST_DUMP_ALL_SOCKET_H

#define PF_INET		2
#define PF_INET6	10

#define EVENT_TYPE_TCP		0
#define EVENT_TYPE_UDP		1
#define EVENT_TYPE_SOCKET	2
#define EVENT_TYPE_INET_ADDR	3
#define EVENT_TYPE_INET6_ADDR	4

#define EVENT_SUBTYPE_ADDR_SRC	0
#define EVENT_SUBTYPE_ADDR_DST	1

struct prog_args {
	int pid;
	int sockfd;
};

struct event_hdr {
	int type;
	int subtype;
	int sockfd;
};

struct event_socket {
	struct event_hdr hdr;
	int family;
	int state;
	int type;
	int protocol;
};

struct event_inet6_addr {
	struct event_hdr hdr;
	struct sockaddr_in6 addr;
};

struct event_inet_addr {
	struct event_hdr hdr;
	struct sockaddr_in addr;
};

struct event_tcp {
	struct event_hdr hdr;
	unsigned int snd_wl1;
	unsigned int snd_wnd;
	unsigned int max_window;
	unsigned int rcv_wnd;
	unsigned int rcv_wup;
	unsigned int write_seq;
	unsigned int rcv_nxt;
};

struct event_udp {
	struct event_hdr hdr;
	int udp_flags;
	int len;
	int pending;
};

#endif /* __TEST_DUMP_ALL_SOCKET_H */
