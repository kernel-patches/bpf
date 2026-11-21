// SPDX-License-Identifier: GPL-2.0-only
/* Send frames through DualPI2 and sample its queue statistics. */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static uint64_t now_us(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts)) {
		perror("clock_gettime");
		exit(1);
	}
	return (uint64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

static unsigned long parse_ulong(const char *s, unsigned long min, unsigned long max)
{
	unsigned long n;
	char *end;

	errno = 0;
	n = strtoul(s, &end, 10);
	if (errno || !*s || *end || n < min || n > max) {
		fprintf(stderr, "invalid number: %s\n", s);
		exit(2);
	}
	return n;
}

static void put_be16(unsigned char *p, unsigned int value)
{
	p[0] = value >> 8;
	p[1] = value & 255;
}

static void ip_checksum(unsigned char *ip)
{
	unsigned int sum = 0;
	unsigned int i;

	ip[10] = 0;
	ip[11] = 0;
	for (i = 0; i < 20; i += 2)
		sum += ((unsigned int)ip[i] << 8) | ip[i + 1];
	while (sum >> 16)
		sum = (sum & 65535) + (sum >> 16);
	put_be16(ip + 10, ~sum & 65535);
}

static int read_stats(const char *dev)
{
	struct {
		struct nlmsghdr n;
		struct tcmsg t;
	} req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg)),
		.n.nlmsg_type = RTM_GETQDISC,
		.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
		.n.nlmsg_seq = 1,
		.t.tcm_family = AF_UNSPEC,
	};
	struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };
	struct timeval timeout = { .tv_sec = 5 };
	union {
		struct nlmsghdr align;
		unsigned char data[16384];
	} buf;
	struct tc_dualpi2_xstats app;
	struct tc_stats stats;
	uint64_t start, end;
	struct sockaddr_nl peer;
	struct iovec iov;
	struct msghdr msg;
	struct nlmsghdr *n;
	struct rtattr *a;
	struct tcmsg *t;
	bool have_app, have_stats, is_dualpi2;
	ssize_t received;
	unsigned int len;
	int fd, alen;

	req.t.tcm_ifindex = if_nametoindex(dev);
	if (!req.t.tcm_ifindex) {
		perror("if_nametoindex");
		return 1;
	}
	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (fd < 0) {
		perror("socket(NETLINK_ROUTE)");
		return 1;
	}
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)))
		goto error;
	start = now_us();
	if (sendto(fd, &req, req.n.nlmsg_len, 0,
		   (struct sockaddr *)&kernel, sizeof(kernel)) < 0)
		goto error;
	for (;;) {
		iov = (struct iovec) { .iov_base = buf.data, .iov_len = sizeof(buf.data) };
		msg = (struct msghdr) {
			.msg_name = &peer,
			.msg_namelen = sizeof(peer),
			.msg_iov = &iov,
			.msg_iovlen = 1,
		};
		received = recvmsg(fd, &msg, 0);
		end = now_us();
		if (received < 0) {
			if (errno == EINTR)
				continue;
			goto error;
		}
		if (!received || msg.msg_flags & MSG_TRUNC) {
			errno = EMSGSIZE;
			goto error;
		}
		if (peer.nl_pid)
			continue;
		len = received;
		for (n = (struct nlmsghdr *)buf.data; NLMSG_OK(n, len);
		     n = NLMSG_NEXT(n, len)) {
			if (n->nlmsg_seq != req.n.nlmsg_seq)
				continue;
			if (n->nlmsg_flags & NLM_F_DUMP_INTR) {
				errno = EAGAIN;
				goto error;
			}
			if (n->nlmsg_type == NLMSG_DONE) {
				errno = ENOENT;
				goto error;
			}
			if (n->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err;

				if (n->nlmsg_len < NLMSG_LENGTH(sizeof(*err))) {
					errno = EPROTO;
					goto error;
				}
				err = NLMSG_DATA(n);
				if (!err->error)
					continue;
				errno = -err->error;
				goto error;
			}
			if (n->nlmsg_type != RTM_NEWQDISC ||
			    n->nlmsg_len < NLMSG_LENGTH(sizeof(*t)))
				continue;
			t = NLMSG_DATA(n);
			if (t->tcm_ifindex != req.t.tcm_ifindex ||
			    t->tcm_handle != TC_H_MAKE(0x10 << 16, 0))
				continue;
			have_app = false;
			have_stats = false;
			is_dualpi2 = false;
			alen = n->nlmsg_len - NLMSG_LENGTH(sizeof(*t));
			for (a = TCA_RTA(t); RTA_OK(a, alen); a = RTA_NEXT(a, alen)) {
				if ((a->rta_type & NLA_TYPE_MASK) == TCA_KIND &&
				    RTA_PAYLOAD(a) == sizeof("dualpi2") &&
				    !memcmp(RTA_DATA(a), "dualpi2", sizeof("dualpi2")))
					is_dualpi2 = true;
				if ((a->rta_type & NLA_TYPE_MASK) == TCA_STATS &&
				    RTA_PAYLOAD(a) >= sizeof(stats)) {
					memcpy(&stats, RTA_DATA(a), sizeof(stats));
					have_stats = true;
				}
				if ((a->rta_type & NLA_TYPE_MASK) == TCA_XSTATS &&
				    RTA_PAYLOAD(a) >= sizeof(app)) {
					memcpy(&app, RTA_DATA(a), sizeof(app));
					have_app = true;
				}
			}
			if (!is_dualpi2 || !have_stats || !have_app) {
				errno = EPROTO;
				goto error;
			}
			printf("%u %u %u %u %u %u %u %" PRIu64 " %" PRIu64 "\n",
			       stats.qlen, app.memory_used, app.delay_c, app.delay_l,
			       app.packets_in_c, app.packets_in_l, app.prob, start, end);
			close(fd);
			return 0;
		}
		if (len) {
			errno = EPROTO;
			goto error;
		}
	}
error:
	perror("RTM_GETQDISC");
	close(fd);
	return 1;
}

int main(int argc, char **argv)
{
	unsigned char frame[ETH_FRAME_LEN];
	struct sockaddr_ll addr = { 0 };
	unsigned char *ip = frame + ETH_HLEN;
	unsigned char *udp = ip + 20;
	uint64_t first, last;
	unsigned int index;
	unsigned long ecn, count, len, i;
	int fd, saved_errno;
	ssize_t ret;

	if (argc == 3 && !strcmp(argv[1], "--stats"))
		return read_stats(argv[2]);
	if (argc == 2 && !strcmp(argv[1], "--now")) {
		printf("%" PRIu64 "\n", now_us());
		return 0;
	}
	if (argc != 4 && argc != 5) {
		fprintf(stderr, "usage: %s DEVICE ECN COUNT [FRAME_BYTES]\n",
			argv[0]);
		fprintf(stderr, "       %s --now\n", argv[0]);
		fprintf(stderr, "       %s --stats DEVICE\n", argv[0]);
		return 2;
	}
	ecn = parse_ulong(argv[2], 0, 3);
	count = parse_ulong(argv[3], 1, 10000);
	len = argc == 5 ? parse_ulong(argv[4], 64, ETH_FRAME_LEN) : 1024;
	index = if_nametoindex(argv[1]);
	if (!index) {
		perror("if_nametoindex");
		return 1;
	}
	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if (fd < 0) {
		saved_errno = errno;
		perror("socket(AF_PACKET)");
		return saved_errno == EPERM || saved_errno == EACCES ? 4 : 1;
	}
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_IP);
	addr.sll_ifindex = index;
	addr.sll_halen = ETH_ALEN;
	addr.sll_addr[0] = 2;
	addr.sll_addr[5] = 2;
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr))) {
		perror("bind(AF_PACKET)");
		close(fd);
		return 1;
	}
	memset(frame, 0, sizeof(frame));
	frame[0] = 2;
	frame[5] = 2;
	frame[6] = 2;
	frame[11] = 1;
	put_be16(frame + 12, ETH_P_IP);
	ip[0] = 0x45;
	ip[1] = ecn;
	put_be16(ip + 2, len - ETH_HLEN);
	ip[8] = 64;
	ip[9] = IPPROTO_UDP;
	ip[12] = 192;
	ip[14] = 2;
	ip[15] = 1;
	ip[16] = 192;
	ip[18] = 2;
	ip[19] = 2;
	put_be16(udp, 4242);
	put_be16(udp + 2, 4243);
	put_be16(udp + 4, len - ETH_HLEN - 20);
	memset(udp + 8, 0x5a, len - ETH_HLEN - 28);

	/* Kernel enqueue timestamps lie between these userspace bounds. */
	first = now_us();
	for (i = 0; i < count; i++) {
		put_be16(ip + 4, i);
		ip_checksum(ip);
		do {
			ret = sendto(fd, frame, len, 0,
				     (struct sockaddr *)&addr, sizeof(addr));
		} while (ret < 0 && errno == EINTR);
		if (ret != (ssize_t)len) {
			if (ret < 0)
				perror("sendto(AF_PACKET)");
			else
				fprintf(stderr, "short packet send: %zd\n", ret);
			close(fd);
			return 1;
		}
	}
	last = now_us();
	close(fd);
	printf("%" PRIu64 " %" PRIu64 "\n", first, last);
	return 0;
}
