// SPDX-License-Identifier: GPL-2.0
/*
 * Helper for sctp_ifwdtsn.sh: I-FORWARD-TSN handling with SCTP user message
 * interleaving (RFC 8260) and partial reliability (RFC 3758).
 *
 * Runs both endpoints of one association: the server socket is created in
 * the current network namespace, the client socket in the namespace given
 * on the command line. The caller sets up the link and any nft rule that
 * drops chunks. Messages sent by the client:
 *
 *   big:    64KB on stream 0, reliable, fragmented into ~66 I-DATA chunks
 *   small:  on stream 1, PR-SCTP "RTX" policy allowing one retransmission;
 *           the nft rule drops (part of) it, so it gets abandoned
 *   marker: short ordered message on stream 0
 *
 * Usage: sctp_ifwdtsn <client netns> <test>
 * Exit status: 0 pass, 1 fail, 4 skip.
 */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/sctp.h>

#include "kselftest.h"

#ifndef SOL_SCTP
#define SOL_SCTP	132
#endif

#define SRV_ADDR	"10.0.0.1"
#define SRV_PORT	5000
#define BIG_LEN		(64 * 1024)
#define BUF_LEN		(BIG_LEN + 1024)
#define MAXSEG		1000
#define TIMEOUT_MS	5000
#define MARKER		"marker"
#define UO_MARKER	"uo-marker"

struct test {
	const char *name;
	bool big_uo;		/* send big unordered */
	int small_len;		/* 0: don't send the small message */
	bool small_uo;		/* send small unordered */
	int pd_point;		/* server SCTP_PARTIAL_DELIVERY_POINT */
	bool expect_pd_abort;	/* PD on stream 1 must be aborted */
	bool uo_marker;		/* then send an unordered marker on 1 */
	bool reset;		/* SSN/TSN association reset after big */
};

static const struct test tests[] = {
	{ .name = "ordered", .small_len = 3000 },
	{ .name = "unordered", .big_uo = true, .small_len = 3000 },
	{ .name = "leading_edge", .small_len = 1000, .pd_point = 2000 },
	{ .name = "uo_pd", .small_len = 20000, .small_uo = true,
	  .pd_point = 2000, .expect_pd_abort = true, .uo_marker = true },
	{ .name = "reset", .reset = true },
};

static const struct test *t;

static void die(const char *what)
{
	fprintf(stderr, "%s: %s\n", what, strerror(errno));
	exit(KSFT_FAIL);
}

static void setopt(int fd, int opt, const void *val, socklen_t len,
		   const char *name)
{
	if (setsockopt(fd, SOL_SCTP, opt, val, len) < 0) {
		fprintf(stderr, "setsockopt(%s): %s\n", name, strerror(errno));
		/* Interleaving disabled, or option not supported. */
		exit(errno == EPERM || errno == ENOPROTOOPT ?
		     KSFT_SKIP : KSFT_FAIL);
	}
}

static void set_assoc_opt(int fd, int opt, unsigned int val, const char *name)
{
	struct sctp_assoc_value av = {
		.assoc_id = SCTP_FUTURE_ASSOC,
		.assoc_value = val,
	};

	setopt(fd, opt, &av, sizeof(av), name);
}

static void subscribe(int fd, int type)
{
	struct sctp_event ev = {
		.se_assoc_id = SCTP_FUTURE_ASSOC,
		.se_type = type,
		.se_on = 1,
	};

	setopt(fd, SCTP_EVENT, &ev, sizeof(ev), "SCTP_EVENT");
}

static int sctp_socket(void)
{
	struct sctp_initmsg im = {
		.sinit_num_ostreams = 2,
		.sinit_max_instreams = 2,
	};
	struct sctp_paddrparams pp = {
		.spp_assoc_id = SCTP_FUTURE_ASSOC,
		.spp_flags = SPP_HB_DISABLE,
	};
	struct sctp_rtoinfo rto = {
		.srto_assoc_id = SCTP_FUTURE_ASSOC,
		.srto_initial = 300,
		.srto_min = 300,
		.srto_max = 1000,
	};
	int fd, val;

	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
	if (fd < 0) {
		perror("socket");
		exit(errno == EPROTONOSUPPORT ? KSFT_SKIP : KSFT_FAIL);
	}
	val = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

	setopt(fd, SCTP_INITMSG, &im, sizeof(im), "SCTP_INITMSG");
	setopt(fd, SCTP_RTOINFO, &rto, sizeof(rto), "SCTP_RTOINFO");
	/* No HEARTBEATs: the nft rules only look at the first chunk of a
	 * packet, and a HEARTBEAT bundled in front of DATA would bypass them.
	 */
	setopt(fd, SCTP_PEER_ADDR_PARAMS, &pp, sizeof(pp),
	       "SCTP_PEER_ADDR_PARAMS");
	set_assoc_opt(fd, SCTP_PR_SUPPORTED, 1, "SCTP_PR_SUPPORTED");
	val = 2;
	setopt(fd, SCTP_FRAGMENT_INTERLEAVE, &val, sizeof(val),
	       "SCTP_FRAGMENT_INTERLEAVE");
	set_assoc_opt(fd, SCTP_INTERLEAVING_SUPPORTED, 1,
		      "SCTP_INTERLEAVING_SUPPORTED");
	if (t->reset) {
		set_assoc_opt(fd, SCTP_RECONFIG_SUPPORTED, 1,
			      "SCTP_RECONFIG_SUPPORTED");
		set_assoc_opt(fd, SCTP_ENABLE_STREAM_RESET,
			      SCTP_ENABLE_RESET_ASSOC_REQ,
			      "SCTP_ENABLE_STREAM_RESET");
		subscribe(fd, SCTP_ASSOC_RESET_EVENT);
	}
	val = 1;
	setopt(fd, SCTP_RECVRCVINFO, &val, sizeof(val), "SCTP_RECVRCVINFO");

	return fd;
}

static void send_msg(int fd, int sid, bool uo, const void *buf, size_t len,
		     bool pr)
{
	char cbuf[CMSG_SPACE(sizeof(struct sctp_sndinfo)) +
		  CMSG_SPACE(sizeof(struct sctp_prinfo))] = {};
	struct iovec iov = { .iov_base = (void *)buf, .iov_len = len };
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cbuf,
		.msg_controllen = CMSG_SPACE(sizeof(struct sctp_sndinfo)),
	};
	struct sctp_sndinfo *si;
	struct sctp_prinfo *pi;
	struct cmsghdr *cm;

	cm = CMSG_FIRSTHDR(&msg);
	cm->cmsg_level = IPPROTO_SCTP;
	cm->cmsg_type = SCTP_SNDINFO;
	cm->cmsg_len = CMSG_LEN(sizeof(*si));
	si = (struct sctp_sndinfo *)CMSG_DATA(cm);
	si->snd_sid = sid;
	si->snd_flags = uo ? SCTP_UNORDERED : 0;

	if (pr) {
		/* Abandon once the chunk would need a second retransmission:
		 * only a chunk that is lost again after being retransmitted
		 * qualifies, so abandonment does not depend on timing.
		 */
		msg.msg_controllen += CMSG_SPACE(sizeof(*pi));
		cm = CMSG_NXTHDR(&msg, cm);
		cm->cmsg_level = IPPROTO_SCTP;
		cm->cmsg_type = SCTP_PRINFO;
		cm->cmsg_len = CMSG_LEN(sizeof(*pi));
		pi = (struct sctp_prinfo *)CMSG_DATA(cm);
		pi->pr_policy = SCTP_PR_SCTP_RTX;
		pi->pr_value = 1;
	}

	if (sendmsg(fd, &msg, 0) != (ssize_t)len)
		die("sendmsg");
}

static unsigned char pattern(size_t i)
{
	return (i * 7 + (i >> 8)) & 0xff;
}

static long long now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000LL + ts.tv_nsec / 1000000;
}

/* Wait until the client has abandoned a sent message. */
static bool wait_abandoned(int fd)
{
	long long end = now_ms() + TIMEOUT_MS;
	struct sctp_prstatus ps;
	socklen_t len;

	while (now_ms() < end) {
		memset(&ps, 0, sizeof(ps));
		ps.sprstat_policy = SCTP_PR_SCTP_RTX;
		len = sizeof(ps);
		if (getsockopt(fd, SOL_SCTP, SCTP_PR_ASSOC_STATUS, &ps,
			       &len) < 0)
			die("SCTP_PR_ASSOC_STATUS");
		if (ps.sprstat_abandoned_sent)
			return true;
		usleep(10000);
	}
	return false;
}

/* Wait for a notification of @type on @fd, discarding anything else. */
static bool wait_event(int fd, int type)
{
	long long end = now_ms() + TIMEOUT_MS;
	char buf[256];

	while (now_ms() < end) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		struct iovec iov = { buf, sizeof(buf) };
		struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1 };
		union sctp_notification *sn = (void *)buf;

		if (poll(&pfd, 1, end - now_ms()) <= 0)
			break;
		if (recvmsg(fd, &msg, 0) <= 0)
			break;
		if ((msg.msg_flags & MSG_NOTIFICATION) &&
		    sn->sn_header.sn_type == type)
			return true;
	}
	return false;
}

/* Bytes held by the server association (/proc/net/sctp/assocs RX_QUEUE). */
static long assoc_rx_queue(void)
{
	/* 7 columns, TX_QUEUE, RX_QUEUE, UID, INODE, LPORT */
	const char *fmt = "%*s %*s %*s %*s %*s %*s %*s %*u %lu %*s %*s %d";
	unsigned long rxq;
	char line[512];
	long ret = -1;
	FILE *f;
	int lport;

	f = fopen("/proc/net/sctp/assocs", "r");
	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, fmt, &rxq, &lport) == 2 && lport == SRV_PORT)
			ret = rxq;
	}
	fclose(f);
	return ret;
}

struct server_state {
	unsigned char *buf[2];	/* message being received, per stream */
	size_t len[2];
	bool big, marker, uo_marker, reset_event;
	int pd_aborts[2];
	int errors;
};

static void check_msg(struct server_state *s, int sid)
{
	unsigned char *m = s->buf[sid];
	size_t len = s->len[sid];
	size_t i;

	s->len[sid] = 0;
	if (sid == 0 && len == sizeof(MARKER) && !memcmp(m, MARKER, len)) {
		s->marker = true;
		return;
	}
	if (sid == 1 && len == sizeof(UO_MARKER) &&
	    !memcmp(m, UO_MARKER, len)) {
		s->uo_marker = true;
		return;
	}
	if (sid == 0 && len == BIG_LEN) {
		for (i = 0; i < BIG_LEN && m[i] == pattern(i); i++)
			;
		if (i == BIG_LEN) {
			s->big = true;
			return;
		}
		printf("big message corrupted at offset %zu\n", i);
	} else if (sid == 1 && len > sizeof(UO_MARKER) &&
		   !memcmp(m + len - sizeof(UO_MARKER), UO_MARKER,
			   sizeof(UO_MARKER))) {
		printf("unordered marker appended to the abandoned message\n");
	} else if (sid == 1 && t->small_len) {
		printf("abandoned message delivered (%zu bytes)\n", len);
	} else {
		printf("unexpected %zu byte message on stream %d\n", len, sid);
	}
	s->errors++;
}

/* Receive until @done(s) is true or the timeout expires. */
static bool server_recv(int fd, struct server_state *s,
			bool (*done)(const struct server_state *s))
{
	long long end = now_ms() + TIMEOUT_MS;
	static char cbuf[CMSG_SPACE(sizeof(struct sctp_rcvinfo))];
	static unsigned char buf[BUF_LEN];

	while (!done(s)) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		struct iovec iov = { buf, sizeof(buf) };
		struct msghdr msg = {
			.msg_iov = &iov,
			.msg_iovlen = 1,
			.msg_control = cbuf,
			.msg_controllen = sizeof(cbuf),
		};
		union sctp_notification *sn = (void *)buf;
		struct sctp_rcvinfo *ri = NULL;
		struct cmsghdr *cm;
		long long left;
		ssize_t n;
		int sid;

		left = end - now_ms();
		if (left <= 0 || poll(&pfd, 1, left) <= 0) {
			printf("timeout waiting for data\n");
			return false;
		}
		n = recvmsg(fd, &msg, 0);
		if (n <= 0) {
			printf("recvmsg: %s\n", n ? strerror(errno) : "EOF");
			return false;
		}

		if (msg.msg_flags & MSG_NOTIFICATION) {
			int type = sn->sn_header.sn_type;

			if (type == SCTP_PARTIAL_DELIVERY_EVENT) {
				sid = sn->sn_pdapi_event.pdapi_stream;
				if (sid > 1)
					sid = 1;
				s->pd_aborts[sid]++;
				s->len[sid] = 0;
			} else if (type == SCTP_ASSOC_RESET_EVENT) {
				s->reset_event = true;
			}
			continue;
		}

		for (cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm))
			if (cm->cmsg_level == IPPROTO_SCTP &&
			    cm->cmsg_type == SCTP_RCVINFO)
				ri = (struct sctp_rcvinfo *)CMSG_DATA(cm);
		sid = ri ? ri->rcv_sid : 0;
		if (sid > 1 || s->len[sid] + n > BUF_LEN) {
			printf("unexpected data on stream %d\n", sid);
			return false;
		}
		memcpy(s->buf[sid] + s->len[sid], buf, n);
		s->len[sid] += n;
		if (msg.msg_flags & MSG_EOR)
			check_msg(s, sid);
	}
	return true;
}

static bool got_big(const struct server_state *s)
{
	return s->big || s->errors;
}

static bool got_all(const struct server_state *s)
{
	return (s->big && s->marker && (!t->uo_marker || s->uo_marker)) ||
	       s->errors;
}

static int client_socket(const char *netns)
{
	int self, other, fd;
	char path[256];

	snprintf(path, sizeof(path), "/run/netns/%s", netns);
	self = open("/proc/self/ns/net", O_RDONLY);
	other = open(path, O_RDONLY);
	if (self < 0 || other < 0)
		die("open netns");
	if (setns(other, CLONE_NEWNET))
		die("setns");
	fd = sctp_socket();
	if (setns(self, CLONE_NEWNET))
		die("setns");
	close(other);
	close(self);
	return fd;
}

int main(int argc, char **argv)
{
	struct sockaddr_in sa = {
		.sin_family = AF_INET,
		.sin_port = htons(SRV_PORT),
	};
	struct server_state s = {};
	unsigned char *big, *small;
	int lfd, sfd, cfd, i;
	sctp_assoc_t id = 0;
	bool ok;
	long rxq;

	if (argc != 3) {
		fprintf(stderr, "usage: %s <client netns> <test>\n", argv[0]);
		return KSFT_FAIL;
	}
	for (i = 0; i < (int)ARRAY_SIZE(tests); i++)
		if (!strcmp(argv[2], tests[i].name))
			t = &tests[i];
	if (!t) {
		fprintf(stderr, "unknown test %s\n", argv[2]);
		return KSFT_FAIL;
	}
	inet_pton(AF_INET, SRV_ADDR, &sa.sin_addr);

	lfd = sctp_socket();
	if (t->pd_point) {
		setopt(lfd, SCTP_PARTIAL_DELIVERY_POINT, &t->pd_point,
		       sizeof(t->pd_point), "SCTP_PARTIAL_DELIVERY_POINT");
		subscribe(lfd, SCTP_PARTIAL_DELIVERY_EVENT);
	}
	if (bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) || listen(lfd, 1))
		die("bind/listen");

	cfd = client_socket(argv[1]);
	set_assoc_opt(cfd, SCTP_MAXSEG, MAXSEG, "SCTP_MAXSEG");
	/* Round robin, so that the small message is sent between fragments
	 * of the big one.
	 */
	set_assoc_opt(cfd, SCTP_STREAM_SCHEDULER, SCTP_SS_RR,
		      "SCTP_STREAM_SCHEDULER");
	if (connect(cfd, (struct sockaddr *)&sa, sizeof(sa)))
		die("connect");
	sfd = accept(lfd, NULL, NULL);
	if (sfd < 0)
		die("accept");

	big = malloc(BIG_LEN);
	small = malloc(t->small_len + 1);
	s.buf[0] = malloc(BUF_LEN);
	s.buf[1] = malloc(BUF_LEN);
	if (!big || !small || !s.buf[0] || !s.buf[1])
		die("malloc");
	for (i = 0; i < BIG_LEN; i++)
		big[i] = pattern(i);
	memset(small, 's', t->small_len);

	send_msg(cfd, 0, t->big_uo, big, BIG_LEN, false);
	if (t->small_len)
		send_msg(cfd, 1, t->small_uo, small, t->small_len, true);

	if (t->reset) {
		ok = server_recv(sfd, &s, got_big);
		if (ok && setsockopt(sfd, SOL_SCTP, SCTP_RESET_ASSOC, &id,
				     sizeof(id)))
			die("SCTP_RESET_ASSOC");
		/* Only send the marker once the reset is done. */
		if (ok && !wait_event(cfd, SCTP_ASSOC_RESET_EVENT)) {
			printf("client: no association reset event\n");
			return KSFT_FAIL;
		}
	}
	send_msg(cfd, 0, false, MARKER, sizeof(MARKER), false);

	if (t->small_len && !wait_abandoned(cfd)) {
		printf("client: small message was not abandoned\n");
		return KSFT_FAIL;
	}
	if (t->uo_marker)
		send_msg(cfd, 1, true, UO_MARKER, sizeof(UO_MARKER), false);

	ok = server_recv(sfd, &s, got_all);
	rxq = assoc_rx_queue();

	if (!s.big)
		printf("big message not delivered intact\n");
	if (!s.marker)
		printf("marker not delivered\n");
	if (t->uo_marker && !s.uo_marker)
		printf("unordered marker not delivered as its own message\n");
	if (s.pd_aborts[0] || (s.pd_aborts[1] && !t->expect_pd_abort)) {
		printf("unexpected partial delivery abort\n");
		ok = false;
	}
	if (t->expect_pd_abort && !s.pd_aborts[1]) {
		printf("partial delivery on stream 1 not aborted\n");
		ok = false;
	}
	if (t->reset && !s.reset_event) {
		printf("server: no association reset event\n");
		ok = false;
	}
	if (rxq < 0) {
		printf("association is gone\n");
		ok = false;
	} else if (rxq > 0) {
		printf("%ld bytes left queued on the association\n", rxq);
		ok = false;
	}

	return ok && !s.errors ? KSFT_PASS : KSFT_FAIL;
}
