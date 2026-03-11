// SPDX-License-Identifier: GPL-2.0
/*
 * BPF audit helpers
 *
 * Borrowed code from tools/selftests/landlock/audit.h
 *
 * Copyright (C) 2024-2025 Microsoft Corporation
 * Copyright (c) 2026 Cloudflare
 */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/audit.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include "audit_helpers.h"

static __u32 seq;

int audit_init(void)
{
	int bufsize = 1024 * 1024; /* 1MB receive buffer */
	struct audit_message msg;
	int fd, err;

	fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_AUDIT);
	if (fd < 0)
		return -errno;

	/*
	 * Increase receive buffer to reduce kernel-side queueing.
	 * When the socket buffer fills up, audit records get queued in
	 * the kernel's hold/retry queues and delivered on subsequent runs.
	 */
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));

	seq = 0;
	err = audit_send(fd, AUDIT_SET, AUDIT_STATUS_ENABLED, 1);
	if (err)
		goto out_close;

	do {
		err = audit_recv(fd, &msg, 0);
		if (err < 0)
			goto out_close;
	} while (msg.nlh.nlmsg_type != NLMSG_ERROR);

	if (msg.err.error)
		goto out_close;

	err = audit_send(fd, AUDIT_SET, AUDIT_STATUS_PID, getpid());
	if (err)
		goto out_close;

	do {
		err = audit_recv(fd, &msg, 0);
		if (err < 0)
			goto out_close;
	} while (msg.nlh.nlmsg_type != NLMSG_ERROR);

	if (msg.err.error)
		goto out_close;

	return fd;

out_close:
	close(fd);
	return err;
}

void audit_cleanup(int fd)
{
	if (fd > 0)
		close(fd);
}

int audit_send(int fd, __u16 type, __u32 key, __u32 val)
{
	struct audit_message msg = {
		.nlh = {
			.nlmsg_len = NLMSG_SPACE(sizeof(msg.status)),
			.nlmsg_type = type,
			.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
			.nlmsg_seq = ++seq,
		},
		.status = {
			.mask = key,
			.enabled = key == AUDIT_STATUS_ENABLED ? val : 0,
			.pid = key == AUDIT_STATUS_PID ? val : 0,
		},
	};
	struct sockaddr_nl addr = { .nl_family = AF_NETLINK };
	int ret;

	do {
		ret = sendto(fd, &msg, msg.nlh.nlmsg_len, 0,
			     (struct sockaddr *)&addr, sizeof(addr));
	} while (ret < 0 && errno == EINTR);

	return ret == msg.nlh.nlmsg_len ? 0 : -errno;
}

/*
 * Receive an audit message from the netlink socket.
 * Returns:
 *   > 0: message type on success
 *   0: ACK received (NLMSG_ERROR with error=0)
 *   < 0: negative errno on error
 */
int audit_recv(int fd, struct audit_message *msg, int flags)
{
	struct sockaddr_nl addr;
	socklen_t addrlen = sizeof(addr);
	int ret;

	do {
		ret = recvfrom(fd, msg, sizeof(*msg), flags,
			       (struct sockaddr *)&addr, &addrlen);
	} while (ret < 0 && errno == EINTR);

	if (ret < 0)
		return -errno;

	/* Must be from kernel (pid 0) */
	if (addrlen != sizeof(addr) || addr.nl_pid != 0)
		return -EINVAL;

	/*
	 * NLMSG_ERROR with error=0 is an ACK. The kernel sends this in
	 * response to messages with NLM_F_ACK flag set.
	 */
	if (msg->nlh.nlmsg_type == NLMSG_ERROR) {
		if (msg->err.error == 0)
			return 0; /* ACK */
		return msg->err.error;
	}

	return msg->nlh.nlmsg_type;
}

__printf(2, 3) static inline void
debug(struct audit_observer *obs, const char *fmt, ...)
{
	va_list args;

	if (!obs || !obs->log)
		return;

	va_start(args, fmt);
	vfprintf(obs->log, fmt, args);
	va_end(args);
}

void audit_observer_init(struct audit_observer *obs, int audit_fd, FILE *log,
			 int wait_timeout_ms)
{
	obs->audit_fd = audit_fd;
	obs->wait_timeout = wait_timeout_ms;

	if (log)
		obs->log = log;

	audit_observer_reset(obs);
}

void audit_observer_reset(struct audit_observer *obs)
{
	memset(obs->expects, 0, sizeof(obs->expects));
	obs->num_expects = 0;
}

int audit_observer_expect(struct audit_observer *obs, int audit_type,
			  const char *pattern, int count)
{
	struct audit_expectation *exp;

	if (obs->num_expects >= AUDIT_EXPECT_MAX)
		return -EINVAL;

	exp = &obs->expects[obs->num_expects++];
	exp->type = audit_type;
	exp->pattern = pattern;
	exp->expected_count = count;
	exp->matched_count = 0;
	return 0;
}

/*
 * Check if a message matches any pending expectation.
 * Returns 1 if all expectations are satisfied, 0 otherwise.
 */
static int audit_observer_match(struct audit_observer *obs,
				struct audit_message *msg)
{
	int all_satisfied = 1;

	for (int i = 0; i < obs->num_expects; i++) {
		struct audit_expectation *exp = &obs->expects[i];

		if (exp->matched_count >= exp->expected_count)
			continue;

		/* Check if this message matches */
		if (exp->type && msg->nlh.nlmsg_type != exp->type)
			goto check_satisfied;

		if (strstr(msg->data, exp->pattern)) {
			exp->matched_count++;
			debug(obs, "%s: matched [%d/%d] %s\n", __func__,
			      exp->matched_count, exp->expected_count,
			      exp->pattern);
		}

check_satisfied:
		if (exp->matched_count < exp->expected_count)
			all_satisfied = 0;
	}

	return all_satisfied;
}

/*
 * Wait for all expected audit messages to arrive.
 * Returns 0 on success (all expectations met), -ETIMEDOUT on timeout.
 */
int audit_observer_wait(struct audit_observer *obs)
{
	struct pollfd pfd = { .fd = obs->audit_fd, .events = POLLIN };
	struct audit_message msg;
	int ret;

	while (1) {
		ret = poll(&pfd, 1, obs->wait_timeout);
		if (ret < 0)
			return -errno;
		if (ret == 0)
			return -ETIMEDOUT;

		memset(&msg, 0, sizeof(msg));
		ret = audit_recv(obs->audit_fd, &msg, MSG_DONTWAIT);

		if (ret == -EAGAIN || ret == -EWOULDBLOCK)
			continue;

		if (ret <= 0)
			continue;

		debug(obs, "%s: recv type=%d %s\n", __func__,
		      msg.nlh.nlmsg_type, msg.data);

		if (audit_observer_match(obs, &msg))
			return 0;
	}
}

int audit_observer_check_satisfied(struct audit_observer *obs)
{
	for (int i = 0; i < obs->num_expects; i++) {
		struct audit_expectation *exp = &obs->expects[i];

		if (exp->matched_count < exp->expected_count) {
			debug(obs, "%s: FAILED pattern '%s' got %d/%d\n",
			      __func__, exp->pattern, exp->matched_count,
			      exp->expected_count);
			return 0;
		}
	}

	return 1;
}
