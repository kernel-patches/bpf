// SPDX-License-Identifier: GPL-2.0
/*
 * Author:
 *	Juntong Deng <juntong.deng@outlook.com>
 */

#ifndef __TEST_RESTORE_UDP_SOCKET_H
#define __TEST_RESTORE_UDP_SOCKET_H

#define EVENT_TYPE_SKB 0
#define EVENT_TYPE_SKB_DATA 1
#define EVENT_TYPE_END 2

#define EVENT_SUBTYPE_RECEIVE_QUEUE 0
#define EVENT_SUBTYPE_WRITE_QUEUE 1
#define EVENT_SUBTYPE_READER_QUEUE 2

struct prog_args {
	int pid;
	int fd;
};

struct event_hdr {
	int type;
	int subtype;
};

struct event_skb {
	struct event_hdr hdr;
	int skb_num;
	int headerlen;
	int len;
	int size;
	int tstamp;
	int dev_scratch;
	int protocol;
	int csum;
	int transport_header;
	int network_header;
	int mac_header;
};

struct event_skb_data {
	struct event_hdr hdr;
	int skb_num;
	int chunk_length;
	int offset;
	char buf[500];
};

#endif /* __TEST_RESTORE_UDP_SOCKET_H */
