// SPDX-License-Identifier: GPL-2.0
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../ksft.h"
#include "xsk_peer.h"

#define XSK_PEER_MAGIC			0x58534b50
#define XSK_PEER_ACCEPT_TMOUT_MS	10000

/*
 * One case per connection; the launcher owns the verdict. As with the control
 * channels of other selftests, the test hosts are trusted: nothing
 * authenticates the peer.
 */
enum xsk_peer_msg_type {
	XSK_PEER_READY = 1,
	XSK_PEER_PROGRESS,
	XSK_PEER_ABORT,
};

struct xsk_peer_msg {
	u32 magic;
	u32 type;
	u32 pkts;
};

struct xsk_peer {
	int fd;
	u32 acked;
	bool ready_seen;
	bool closed;
};

static int io_full(int fd, void *buf, size_t len, bool write_op)
{
	size_t done = 0;
	ssize_t ret;

	while (done < len) {
		if (write_op)
			ret = send(fd, (char *)buf + done, len - done, MSG_NOSIGNAL);
		else
			ret = read(fd, (char *)buf + done, len - done);
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret < 0)
			return -errno;
		if (!ret)
			return -EPIPE;
		done += ret;
	}
	return 0;
}

/*
 * Past its last barrier the peer may exit at any time, and it resets the
 * connection if our progress reports are still unread.
 */
static bool peer_gone(int err)
{
	return err == -EPIPE || err == -ECONNRESET;
}

static int peer_send(struct xsk_peer *peer, u32 type, u32 pkts)
{
	struct xsk_peer_msg msg = {
		.magic = htonl(XSK_PEER_MAGIC),
		.type = htonl(type),
		.pkts = htonl(pkts),
	};

	return io_full(peer->fd, &msg, sizeof(msg), true);
}

static int peer_recv_one(struct xsk_peer *peer)
{
	struct xsk_peer_msg msg;
	u32 pkts;
	int err;

	err = io_full(peer->fd, &msg, sizeof(msg), false);
	if (peer_gone(err))
		peer->closed = true;
	if (err)
		return err;
	if (ntohl(msg.magic) != XSK_PEER_MAGIC)
		return -EPROTO;

	switch (ntohl(msg.type)) {
	case XSK_PEER_READY:
		/* The peer waits for our READY, so it is at most one step ahead. */
		if (peer->ready_seen)
			return -EPROTO;
		peer->ready_seen = true;
		return 0;
	case XSK_PEER_PROGRESS:
		/* xsk_peer_tx_sync() returns the sum as an int. */
		pkts = ntohl(msg.pkts);
		if (pkts > INT_MAX - peer->acked)
			return -EPROTO;
		peer->acked += pkts;
		return 0;
	case XSK_PEER_ABORT:
		return -ECANCELED;
	default:
		return -EPROTO;
	}
}

/*
 * Consume what the peer has sent so far without blocking. A closed connection
 * is not an error here, see peer_gone(); xsk_peer_closed() reports it.
 */
static int peer_drain(struct xsk_peer *peer)
{
	struct pollfd pfd = { .fd = peer->fd, .events = POLLIN };
	int ret;

	while (!peer->closed) {
		ret = poll(&pfd, 1, 0);
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret < 0)
			return -errno;
		if (!ret)
			break;
		ret = peer_recv_one(peer);
		if (ret && !peer->closed)
			return ret;
	}
	return 0;
}

/* Return once both endpoints are set up for the next step. */
int xsk_peer_ready(struct xsk_peer *peer)
{
	int err;

	err = peer_send(peer, XSK_PEER_READY, 0);
	while (!err && !peer->ready_seen)
		err = peer_recv_one(peer);
	if (err)
		return err;

	/* TCP ordering puts all progress of the previous step before READY. */
	peer->ready_seen = false;
	peer->acked = 0;
	return 0;
}

void xsk_peer_abort(struct xsk_peer *peer)
{
	if (peer && !peer->closed)
		peer_send(peer, XSK_PEER_ABORT, 0);
}

int xsk_peer_rx_progress(struct xsk_peer *peer, u32 pkts)
{
	int err;

	if (pkts && !peer->closed) {
		err = peer_send(peer, XSK_PEER_PROGRESS, pkts);
		/*
		 * Leave closed to peer_drain(), which first reads what the
		 * peer sent before it went away, such as an ABORT.
		 */
		if (err && !peer_gone(err))
			return err;
	}
	return peer_drain(peer);
}

/* Return the packets RX reported consumed since the last call, or -errno. */
int xsk_peer_tx_sync(struct xsk_peer *peer)
{
	int err = peer_drain(peer);
	u32 acked = peer->acked;

	if (err)
		return err;
	peer->acked = 0;
	return acked;
}

bool xsk_peer_closed(struct xsk_peer *peer)
{
	return peer->closed;
}

static int accept_tmout(int lfd)
{
	struct pollfd pfd = { .fd = lfd, .events = POLLIN };
	int ret;

	do {
		ret = poll(&pfd, 1, XSK_PEER_ACCEPT_TMOUT_MS);
	} while (ret < 0 && errno == EINTR);
	if (!ret)
		errno = ETIMEDOUT;
	return ret > 0 ? accept(lfd, NULL, NULL) : -1;
}

/*
 * The listener tells the launcher with ksft_ready() once it listens, and the
 * launcher starts the connector only then, so connect() needs no retry.
 * accept() is bounded in case the connector exits before it gets that far.
 */
static int peer_open_tcp(const char *host, const char *port, bool listen_side)
{
	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
		.ai_flags = AI_NUMERICSERV,
	};
	int fd = -1, lfd, saved = ECONNREFUSED, one = 1, err;
	struct addrinfo *res, *ai;

	err = getaddrinfo(host, port, &hints, &res);
	if (err)
		return -EINVAL;

	if (!listen_side)
		goto conn;

	for (ai = res; ai; ai = ai->ai_next) {
		lfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (lfd < 0)
			continue;
		setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
		if (!bind(lfd, ai->ai_addr, ai->ai_addrlen) && !listen(lfd, 1)) {
			ksft_ready();
			fd = accept_tmout(lfd);
			saved = errno;
			close(lfd);
			break;
		}
		saved = errno;
		close(lfd);
	}
	freeaddrinfo(res);
	return fd >= 0 ? fd : -saved;

conn:
	for (ai = res; ai; ai = ai->ai_next) {
		fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd < 0)
			continue;
		if (!connect(fd, ai->ai_addr, ai->ai_addrlen))
			break;
		saved = errno;
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	return fd >= 0 ? fd : -saved;
}

struct xsk_peer *xsk_peer_open(const char *host, const char *port,
			       bool listen_side)
{
	int fd = peer_open_tcp(host, port, listen_side);
	struct xsk_peer *peer;
	int one = 1;

	if (fd < 0) {
		errno = -fd;
		return NULL;
	}
	peer = calloc(1, sizeof(*peer));
	if (!peer) {
		close(fd);
		return NULL;
	}
	peer->fd = fd;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	return peer;
}

void xsk_peer_close(struct xsk_peer *peer)
{
	if (peer) {
		close(peer->fd);
		free(peer);
	}
}
