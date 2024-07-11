// SPDX-License-Identifier: GPL-2.0
/*
 * Author:
 *	Juntong Deng <juntong.deng@outlook.com>
 */

#include <argp.h>
#include <stdio.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <linux/netlink.h>
#include <asm/types.h>

#include "../kselftest_harness.h"

#include "test_restore_udp_socket.h"
#include "test_restore_udp_socket.bpf.skel.h"

static int sockfd_checkpoint;
static int sockfd_restore;
static int sockfd_client;
static int sockfd_server;

static int dump_socket_queue_fd;
static int restore_socket_queue_fd;

static struct ring_buffer *rb;
static struct user_ring_buffer *urb;

char buffer_send1[1000], buffer_send2[1000];
char buffer_recv1[1000], buffer_recv2[1000];

static int last_skb_num = -1;
static int last_skb_transport_header;

static int handle_dump_end_event(void)
{
	struct prog_args arg_restore = {
		.pid = getpid(),
		.fd = sockfd_restore
	};

	DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts,
		.ctx_in = &arg_restore,
		.ctx_size_in = sizeof(arg_restore),
	);

	int err = bpf_prog_test_run_opts(restore_socket_queue_fd, &opts);
	return err;
}

static int handle_dump_skb_data_event(struct event_skb_data *e_skb_data)
{
	if (e_skb_data->hdr.subtype == EVENT_SUBTYPE_WRITE_QUEUE) {
		if (last_skb_num != e_skb_data->skb_num) {
			send(sockfd_restore, e_skb_data->buf + last_skb_transport_header + 8,
				e_skb_data->chunk_length - last_skb_transport_header - 8, 0);
			last_skb_num = e_skb_data->skb_num;
		} else {
			send(sockfd_restore, e_skb_data->buf, e_skb_data->chunk_length, 0);
		}
	} else {
		struct event_skb_data *e_restore_skb_data = (struct event_skb_data *)user_ring_buffer__reserve(urb, sizeof(struct event_skb_data));
		if (!e_restore_skb_data) {
			printf("user_ring_buffer__reserve error\n");
			return -2;
		}

		e_restore_skb_data->hdr.type = EVENT_TYPE_SKB_DATA;
		e_restore_skb_data->hdr.subtype = e_skb_data->hdr.subtype;
		e_restore_skb_data->skb_num = e_skb_data->skb_num;
		e_restore_skb_data->chunk_length = e_skb_data->chunk_length;
		e_restore_skb_data->offset = e_skb_data->offset;
		memcpy(e_restore_skb_data->buf, e_skb_data->buf, e_skb_data->chunk_length);

		user_ring_buffer__submit(urb, e_restore_skb_data);
	}
	return 0;
}

static int handle_dump_skb_event(struct event_skb *e_skb)
{
	if (e_skb->hdr.subtype == EVENT_SUBTYPE_WRITE_QUEUE) {
		last_skb_transport_header = e_skb->transport_header;
		return 0;
	}

	struct event_skb *e_restore_skb = (struct event_skb *)user_ring_buffer__reserve(urb, sizeof(struct event_skb));
	if (!e_restore_skb) {
		printf("user_ring_buffer__reserve error\n");
		return -2;
	}

	e_restore_skb->hdr.type = EVENT_TYPE_SKB;
	e_restore_skb->hdr.subtype = e_skb->hdr.subtype;
	e_restore_skb->skb_num = e_skb->skb_num;
	e_restore_skb->len = e_skb->len;
	e_restore_skb->headerlen = e_skb->headerlen;
	e_restore_skb->size = e_skb->size;
	e_restore_skb->tstamp = e_skb->tstamp;
	e_restore_skb->dev_scratch = e_skb->dev_scratch;
	e_restore_skb->protocol = e_skb->protocol;
	e_restore_skb->csum = e_skb->csum;
	e_restore_skb->transport_header = e_skb->transport_header;
	e_restore_skb->network_header = e_skb->network_header;
	e_restore_skb->mac_header = e_skb->mac_header;

	user_ring_buffer__submit(urb, e_restore_skb);
	return 0;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event_hdr *e_hdr = data;
	int err = 0;

	switch (e_hdr->type) {
	case EVENT_TYPE_SKB:
		handle_dump_skb_event((struct event_skb *)data);
		break;
	case EVENT_TYPE_SKB_DATA:
		handle_dump_skb_data_event((struct event_skb_data *)data);
		break;
	case EVENT_TYPE_END:
		handle_dump_end_event();
		break;
	default:
		err = -1;
		printf("Unknown event type!\n");
		break;
	}
	return err;
}

static int check_restore_data_correctness(void)
{
	const int disable = 0;
	if (setsockopt(sockfd_restore, IPPROTO_UDP, UDP_CORK, &disable, sizeof(disable)))
		return -1;

	char buffer1[1000], buffer2[2000];
	memset(buffer1, 0, sizeof(buffer1));
	memset(buffer2, 0, sizeof(buffer2));

	struct sockaddr_in src_addr, client_src_addr;
	socklen_t sockaddr_len = sizeof(struct sockaddr_in);
	memset(&src_addr, 0, sizeof(struct sockaddr_in));
	memset(&client_src_addr, 0, sizeof(struct sockaddr_in));

	if (getsockname(sockfd_client, (struct sockaddr *)&client_src_addr, &sockaddr_len))
		return -1;

	if (recvfrom(sockfd_restore, buffer1, sizeof(buffer1), 0, (struct sockaddr *)&src_addr, &sockaddr_len) <= 0)
		return -1;

	if (memcmp(buffer1, buffer_recv1, sizeof(buffer_recv1)) != 0)
		return -1;

	if (src_addr.sin_addr.s_addr != htonl(INADDR_LOOPBACK) || src_addr.sin_port != client_src_addr.sin_port)
		return -1;

	if (recvfrom(sockfd_restore, buffer1, sizeof(buffer1), 0, (struct sockaddr *)&src_addr, &sockaddr_len) <= 0)
		return -1;

	if (memcmp(buffer1, buffer_recv2, sizeof(buffer_recv2)) != 0)
		return -1;

	if (src_addr.sin_addr.s_addr != htonl(INADDR_LOOPBACK) || src_addr.sin_port != client_src_addr.sin_port)
		return -1;

	if (recvfrom(sockfd_server, buffer2, sizeof(buffer2), 0, (struct sockaddr *)&src_addr, &sockaddr_len) <= 0)
		return -1;

	if (memcmp(buffer2, buffer_send1, sizeof(buffer_send1)) != 0)
		return -1;

	if (memcmp(buffer2 + sizeof(buffer_send1), buffer_send2, sizeof(buffer_send2)) != 0)
		return -1;

	return 0;
}

static int check_restore_socket(void)
{
	/*
	 * Check that the restore socket can continue to work properly
	 * (the restore process did not damage the socket)
	 */
	char buffer[1000];
	memset(buffer, 0, sizeof(buffer));

	struct sockaddr_in src_addr, restore_src_addr;
	socklen_t sockaddr_len = sizeof(struct sockaddr_in);
	memset(&src_addr, 0, sizeof(struct sockaddr_in));
	memset(&restore_src_addr, 0, sizeof(struct sockaddr_in));

	if (getsockname(sockfd_restore, (struct sockaddr *)&restore_src_addr, &sockaddr_len))
		return -1;

	if (connect(sockfd_server, (struct sockaddr *)&restore_src_addr, sizeof(struct sockaddr_in)) < 0)
		return -1;

	if (send(sockfd_restore, buffer_send1, sizeof(buffer_send1), 0) <= 0)
		return -1;

	if (send(sockfd_server, buffer_send2, sizeof(buffer_send2), 0) <= 0)
		return -1;

	if (recvfrom(sockfd_server, buffer, sizeof(buffer), 0, (struct sockaddr *)&src_addr, &sockaddr_len) <= 0)
		return -1;

	if (memcmp(buffer, buffer_send1, sizeof(buffer_send1)) != 0)
		return -1;

	if (recvfrom(sockfd_restore, buffer, sizeof(buffer), 0, (struct sockaddr *)&src_addr, &sockaddr_len) <= 0)
		return -1;

	if (memcmp(buffer, buffer_send2, sizeof(buffer_send2)) != 0)
		return -1;

	if (src_addr.sin_addr.s_addr != htonl(INADDR_LOOPBACK) || src_addr.sin_port != htons(6003))
		return -1;

	return 0;
}

TEST(restore_udp_socket)
{
	sockfd_checkpoint = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
	ASSERT_GT(sockfd_checkpoint, 0);

	sockfd_restore = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
	ASSERT_GT(sockfd_restore, 0);

	sockfd_client = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
	ASSERT_GT(sockfd_client, 0);

	sockfd_server = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
	ASSERT_GT(sockfd_server, 0);

	struct sockaddr_in checkpoint_src_addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_ANY),
		.sin_port = htons(6001)
	};

	struct sockaddr_in checkpoint_dst_addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = htons(6002)
	};

	struct sockaddr_in restore_dst_addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = htons(6003)
	};

	const int enable = 1;
	ASSERT_EQ(setsockopt(sockfd_checkpoint, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)), 0);
	ASSERT_EQ(setsockopt(sockfd_server, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)), 0);

	ASSERT_EQ(setsockopt(sockfd_checkpoint, IPPROTO_UDP, UDP_CORK, &enable, sizeof(enable)), 0);
	ASSERT_EQ(setsockopt(sockfd_restore, IPPROTO_UDP, UDP_CORK, &enable, sizeof(enable)), 0);

	ASSERT_EQ(bind(sockfd_checkpoint, (struct sockaddr *)&checkpoint_src_addr, sizeof(struct sockaddr_in)), 0);
	ASSERT_EQ(bind(sockfd_server, (struct sockaddr *)&restore_dst_addr, sizeof(struct sockaddr_in)), 0);

	memset(buffer_send1, 'a', 1000);
	memset(buffer_send2, 'b', 1000);
	memset(buffer_recv1, 'c', 1000);
	memset(buffer_recv2, 'd', 1000);

	ASSERT_EQ(connect(sockfd_client, (struct sockaddr *)&checkpoint_src_addr, sizeof(struct sockaddr_in)), 0);
	ASSERT_EQ(send(sockfd_client, buffer_recv1, sizeof(buffer_recv1), 0), sizeof(buffer_recv1));
	ASSERT_EQ(send(sockfd_client, buffer_recv2, sizeof(buffer_recv2), 0), sizeof(buffer_recv2));

	ASSERT_EQ(connect(sockfd_checkpoint, (struct sockaddr *)&checkpoint_dst_addr, sizeof(struct sockaddr_in)), 0);
	ASSERT_EQ(connect(sockfd_restore, (struct sockaddr *)&restore_dst_addr, sizeof(struct sockaddr_in)), 0);

	ASSERT_EQ(send(sockfd_checkpoint, buffer_send1, sizeof(buffer_send1), 0), sizeof(buffer_send1));
	ASSERT_EQ(send(sockfd_checkpoint, buffer_send2, sizeof(buffer_send2), 0), sizeof(buffer_send2));

	struct prog_args arg_checkpoint = {
		.pid = getpid(),
		.fd = sockfd_checkpoint
	};

	DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts,
		.ctx_in = &arg_checkpoint,
		.ctx_size_in = sizeof(arg_checkpoint),
	);

	struct test_restore_udp_socket_bpf *skel = test_restore_udp_socket_bpf__open_and_load();
	dump_socket_queue_fd = bpf_program__fd(skel->progs.dump_socket_queue);
	restore_socket_queue_fd = bpf_program__fd(skel->progs.restore_socket_queue);

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	ASSERT_NE(rb, NULL);

	urb = user_ring_buffer__new(bpf_map__fd(skel->maps.urb), NULL);
	ASSERT_NE(urb, NULL);

	ASSERT_EQ(bpf_prog_test_run_opts(dump_socket_queue_fd, &opts), 0);

	ASSERT_GT(ring_buffer__poll(rb, 100), 0);

	ASSERT_EQ(check_restore_data_correctness(), 0);
	ASSERT_EQ(check_restore_socket(), 0);

	ASSERT_EQ(close(sockfd_checkpoint), 0);
	ASSERT_EQ(close(sockfd_restore), 0);
	ASSERT_EQ(close(sockfd_client), 0);
	ASSERT_EQ(close(sockfd_server), 0);
	ring_buffer__free(rb);
	user_ring_buffer__free(urb);
	test_restore_udp_socket_bpf__destroy(skel);
}

TEST_HARNESS_MAIN
