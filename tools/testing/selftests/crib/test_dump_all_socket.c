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
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <linux/netlink.h>
#include <asm/types.h>
#include <asm-generic/socket.h>
#include <linux/tcp.h>

#include "../kselftest_harness.h"

#include "test_dump_all_socket.h"
#include "test_dump_all_socket.bpf.skel.h"

struct tcp_dump_info {
	unsigned int snd_wl1;
	unsigned int snd_wnd;
	unsigned int max_window;
	unsigned int rcv_wnd;
	unsigned int rcv_wup;
	unsigned int write_seq;
	unsigned int rcv_nxt;
};

struct udp_dump_info {
	int udp_flags;
	int len;
	int pending;
};

struct socket_dump_info {
	int sockfd;
	int family;
	int type;
	int protocol;
	union {
		struct sockaddr_in src_addr4;
		struct sockaddr_in6 src_addr6;
	};
	union {
		struct sockaddr_in dst_addr4;
		struct sockaddr_in6 dst_addr6;
	};
	union {
		struct tcp_dump_info tcp;
		struct udp_dump_info udp;
	};
};

static int dump_all_socket_fd;
static int dump_tcp_socket_fd;
static int dump_udp_socket_fd;

static int tcp_client_fd;
static int tcp_server_fd;
static int tcp_accept_fd;
static int udp_client_fd;

static int socket_count;

static struct socket_dump_info *find_dump_info_by_sockfd(struct socket_dump_info *all_info, int sockfd)
{
	struct socket_dump_info *info;
	for (int i = 0; i < 4; i++) {
		info = &all_info[i];
		if (info->sockfd == sockfd)
			return info;
	}
	return NULL;
}

static int handle_tcp_event(struct socket_dump_info *all_info, struct event_tcp *e_tcp)
{
	struct socket_dump_info *info = find_dump_info_by_sockfd(all_info, e_tcp->hdr.sockfd);
	info->tcp.snd_wl1 = e_tcp->snd_wl1;
	info->tcp.snd_wnd = e_tcp->snd_wnd;
	info->tcp.max_window = e_tcp->max_window;
	info->tcp.rcv_wnd = e_tcp->rcv_wnd;
	info->tcp.rcv_wup = e_tcp->rcv_wup;
	info->tcp.write_seq = e_tcp->write_seq;
	info->tcp.rcv_nxt = e_tcp->rcv_nxt;
	return 0;
}

static int handle_udp_event(struct socket_dump_info *all_info, struct event_udp *e_udp)
{
	struct socket_dump_info *info = find_dump_info_by_sockfd(all_info, e_udp->hdr.sockfd);
	info->udp.udp_flags = e_udp->udp_flags;
	info->udp.len = e_udp->len;
	info->udp.pending = e_udp->pending;
	return 0;
}

static int handle_inet_addr_event(struct socket_dump_info *all_info, struct event_inet_addr *e_inet_addr)
{
	struct socket_dump_info *info = &all_info[socket_count - 1];
	if (e_inet_addr->hdr.subtype == EVENT_SUBTYPE_ADDR_SRC)
		memcpy(&info->src_addr4, &e_inet_addr->addr, sizeof(struct sockaddr_in));
	else if (e_inet_addr->hdr.subtype == EVENT_SUBTYPE_ADDR_DST)
		memcpy(&info->dst_addr4, &e_inet_addr->addr, sizeof(struct sockaddr_in));
	return 0;
}

static int handle_inet6_addr_event(struct socket_dump_info *all_info, struct event_inet6_addr *e_inet6_addr)
{
	struct socket_dump_info *info = &all_info[socket_count - 1];
	if (e_inet6_addr->hdr.subtype == EVENT_SUBTYPE_ADDR_SRC)
		memcpy(&info->src_addr6, &e_inet6_addr->addr, sizeof(struct sockaddr_in6));
	else if (e_inet6_addr->hdr.subtype == EVENT_SUBTYPE_ADDR_DST)
		memcpy(&info->dst_addr6, &e_inet6_addr->addr, sizeof(struct sockaddr_in6));
	return 0;
}

static int handle_socket_event(struct socket_dump_info *all_info, struct event_socket *e_socket)
{
	struct prog_args arg = {
		.pid = getpid(),
		.sockfd = e_socket->hdr.sockfd
	};

	DECLARE_LIBBPF_OPTS(bpf_test_run_opts, tattrs,
		.ctx_in = &arg,
		.ctx_size_in = sizeof(arg),
	);

	struct socket_dump_info *info = &all_info[socket_count];
	info->sockfd = e_socket->hdr.sockfd;
	info->family = e_socket->family;
	info->type = e_socket->type;
	info->protocol = e_socket->protocol;

	int err = 0;
	if (e_socket->protocol == IPPROTO_TCP)
		err = bpf_prog_test_run_opts(dump_tcp_socket_fd, &tattrs);
	else if (e_socket->protocol == IPPROTO_UDP)
		err = bpf_prog_test_run_opts(dump_udp_socket_fd, &tattrs);

	socket_count++;

	return err;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct socket_dump_info *all_info = (struct socket_dump_info *)ctx;
	const struct event_hdr *e_hdr = data;
	int err = 0;

	switch (e_hdr->type) {
	case EVENT_TYPE_TCP:
		handle_tcp_event(all_info, (struct event_tcp *)data);
		break;
	case EVENT_TYPE_UDP:
		handle_udp_event(all_info, (struct event_udp *)data);
		break;
	case EVENT_TYPE_SOCKET:
		handle_socket_event(all_info, (struct event_socket *)data);
		break;
	case EVENT_TYPE_INET_ADDR:
		handle_inet_addr_event(all_info, (struct event_inet_addr *)data);
		break;
	case EVENT_TYPE_INET6_ADDR:
		handle_inet6_addr_event(all_info, (struct event_inet6_addr *)data);
		break;
	default:
		err = -1;
		printf("Unknown event type!\n");
		break;
	}
	return err;
}

static int check_tcp_dump_info_correctness(struct socket_dump_info *info)
{
	const int enable = 1;
	if (info->family != AF_INET || info->type != SOCK_STREAM ||
		info->protocol != IPPROTO_TCP)
		return -1;

	if (info->dst_addr4.sin_family != AF_INET || info->src_addr4.sin_family != AF_INET)
		return -1;

	if (info->sockfd == tcp_client_fd && (info->dst_addr4.sin_addr.s_addr != htonl(INADDR_LOOPBACK) ||
		info->dst_addr4.sin_port != htons(5555)))
		return -1;

	if (info->sockfd == tcp_server_fd && (info->src_addr4.sin_addr.s_addr != htonl(INADDR_ANY) ||
		info->src_addr4.sin_port != htons(5555)))
		return -1;

	if (info->sockfd == tcp_accept_fd && (info->src_addr4.sin_addr.s_addr != htonl(INADDR_LOOPBACK) ||
		info->dst_addr4.sin_addr.s_addr != htonl(INADDR_LOOPBACK) ||
		info->src_addr4.sin_port != htons(5555)))
		return -1;

	if (info->sockfd != tcp_server_fd) {
		if (setsockopt(info->sockfd, IPPROTO_TCP, TCP_REPAIR, &enable, sizeof(enable)))
			return -1;

		struct tcp_repair_window opt;
		socklen_t optlen = sizeof(opt);
		if (getsockopt(info->sockfd, IPPROTO_TCP, TCP_REPAIR_WINDOW, &opt, &optlen))
			return -1;

		if (opt.snd_wl1 != info->tcp.snd_wl1 || opt.snd_wnd != info->tcp.snd_wnd ||
			opt.max_window != info->tcp.max_window || opt.rcv_wnd != info->tcp.rcv_wnd ||
			opt.rcv_wup != info->tcp.rcv_wup)
			return -1;

		int queue = TCP_SEND_QUEUE;
		if (setsockopt(info->sockfd, IPPROTO_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue)))
			return -1;

		unsigned int write_seq;
		optlen = sizeof(write_seq);
		if (getsockopt(info->sockfd, IPPROTO_TCP, TCP_QUEUE_SEQ, &write_seq, &optlen))
			return -1;

		if (write_seq != info->tcp.write_seq)
			return -1;

		queue = TCP_RECV_QUEUE;
		if (setsockopt(info->sockfd, IPPROTO_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue)))
			return -1;

		unsigned int rcv_nxt;
		if (getsockopt(info->sockfd, IPPROTO_TCP, TCP_QUEUE_SEQ, &rcv_nxt, &optlen))
			return -1;

		if (rcv_nxt != info->tcp.rcv_nxt)
			return -1;
	}
	return 0;
}

static int check_udp_dump_info_correctness(struct socket_dump_info *info)
{
	if (info->family != AF_INET6 || info->type != SOCK_DGRAM ||
		info->protocol != IPPROTO_UDP)
		return -1;

	if (info->dst_addr6.sin6_family != AF_INET6 || info->dst_addr6.sin6_port != htons(7777) ||
		memcmp(&info->dst_addr6.sin6_addr, &in6addr_loopback, sizeof(struct in6_addr)) != 0)
		return -1;

	return 0;
}

static int check_dump_info_correctness(struct socket_dump_info *all_info)
{
	struct socket_dump_info *info;
	for (int i = 0; i < 4; i++) {
		info = &all_info[i];

		if (info->sockfd <= 0)
			return -1;

		if (info->sockfd == udp_client_fd) {
			if (check_udp_dump_info_correctness(info) != 0)
				return -1;
		} else {
			if (check_tcp_dump_info_correctness(info) != 0)
				return -1;
		}

	}
	return 0;
}

TEST(dump_all_socket)
{
	struct prog_args args = {
		.pid = getpid(),
	};
	ASSERT_GT(args.pid, 0);

	DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts,
		.ctx_in = &args,
		.ctx_size_in = sizeof(args),
	);

	tcp_client_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	ASSERT_GT(tcp_client_fd, 0);

	tcp_server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	ASSERT_GT(tcp_server_fd, 0);

	udp_client_fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	ASSERT_GT(udp_client_fd, 0);

	const int enable = 1;
	ASSERT_EQ(setsockopt(tcp_server_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)), 0);

	struct sockaddr_in tcp_src_addr, tcp_dst_addr;
	struct sockaddr_in6 udp_dst_addr;
	memset(&tcp_src_addr, 0, sizeof(struct sockaddr_in));
	memset(&tcp_dst_addr, 0, sizeof(struct sockaddr_in));
	memset(&udp_dst_addr, 0, sizeof(struct sockaddr_in6));

	tcp_src_addr.sin_family = AF_INET;
	tcp_src_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	tcp_src_addr.sin_port = htons(5555);

	tcp_dst_addr.sin_family = AF_INET;
	tcp_dst_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	tcp_dst_addr.sin_port = htons(5555);

	udp_dst_addr.sin6_family = AF_INET6;
	udp_dst_addr.sin6_addr = in6addr_loopback;
	udp_dst_addr.sin6_port = htons(7777);

	ASSERT_EQ(bind(tcp_server_fd, (struct sockaddr *)&tcp_src_addr, sizeof(struct sockaddr_in)), 0);
	ASSERT_EQ(listen(tcp_server_fd, 100), 0);

	ASSERT_EQ(connect(tcp_client_fd, (struct sockaddr *)&tcp_dst_addr, sizeof(struct sockaddr_in)), 0);

	tcp_accept_fd = accept(tcp_server_fd, NULL, NULL);
	ASSERT_GT(tcp_accept_fd, 0);

	char buf[20];
	memset(buf, 'a', 20);
	ASSERT_EQ(send(tcp_client_fd, buf, 20, 0), 20);

	ASSERT_EQ(connect(udp_client_fd, (struct sockaddr *)&udp_dst_addr, sizeof(struct sockaddr_in6)), 0);

	struct test_dump_all_socket_bpf *skel = test_dump_all_socket_bpf__open_and_load();
	ASSERT_NE(skel, NULL);

	dump_all_socket_fd = bpf_program__fd(skel->progs.dump_all_socket);
	ASSERT_GT(dump_all_socket_fd, 0);

	dump_tcp_socket_fd = bpf_program__fd(skel->progs.dump_tcp_socket);
	ASSERT_GT(dump_tcp_socket_fd, 0);

	dump_udp_socket_fd = bpf_program__fd(skel->progs.dump_udp_socket);
	ASSERT_GT(dump_udp_socket_fd, 0);

	struct socket_dump_info *all_info = (struct socket_dump_info *)malloc(sizeof(struct socket_dump_info) * 4);

	struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, all_info, NULL);
	ASSERT_NE(rb, NULL);

	ASSERT_EQ(bpf_prog_test_run_opts(dump_all_socket_fd, &opts), 0);

	ASSERT_GT(ring_buffer__poll(rb, 100), 0);

	ASSERT_EQ(check_dump_info_correctness(all_info), 0);

	ASSERT_EQ(close(tcp_client_fd), 0);
	ASSERT_EQ(close(tcp_accept_fd), 0);
	ASSERT_EQ(close(tcp_server_fd), 0);
	ASSERT_EQ(close(udp_client_fd), 0);
	ring_buffer__free(rb);
	test_dump_all_socket_bpf__destroy(skel);
}

TEST_HARNESS_MAIN
