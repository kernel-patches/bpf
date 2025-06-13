// SPDX-License-Identifier: GPL-2.0
/* Copyright 2025 Google LLC */

#include "test_progs.h"
#include "lsm_unix_may_send.skel.h"

#define MSG_HELLO "Hello"
#define MSG_WORLD "World"
#define MSG_LEN 5

struct scm_rights {
	struct cmsghdr cmsghdr;
	int fd;
};

static int send_fd(int sender_fd, int receiver_fd, bool lsm_attached)
{
	struct scm_rights cmsg = {};
	struct msghdr msg = {};
	struct iovec iov = {};
	int ret;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = &cmsg;
	msg.msg_controllen = CMSG_SPACE(sizeof(cmsg.fd));

	iov.iov_base = MSG_HELLO;
	iov.iov_len = MSG_LEN;

	cmsg.cmsghdr.cmsg_len = CMSG_LEN(sizeof(cmsg.fd));
	cmsg.cmsghdr.cmsg_level = SOL_SOCKET;
	cmsg.cmsghdr.cmsg_type = SCM_RIGHTS;
	cmsg.fd = receiver_fd;

	/* sending "Hello" with the receiver's fd. */
	ret = sendmsg(sender_fd, &msg, 0);

	if (lsm_attached) {
		if (!ASSERT_EQ(ret, -1, "sendmsg(Hello)") ||
		    !ASSERT_EQ(errno, EPERM, "sendmsg(Hello) errno"))
			return -EINVAL;
	} else {
		if (!ASSERT_EQ(ret, MSG_LEN, "sendmsg(Hello)"))
			return -EINVAL;
	}

	/* sending "World" without SCM_RIGHTS. */
	ret = send(sender_fd, MSG_WORLD, MSG_LEN, 0);
	if (!ASSERT_EQ(ret, MSG_LEN, "sendmsg(World)"))
		return -EINVAL;

	return 0;
}

static int recv_fd(int receiver_fd, bool lsm_attached)
{
	struct scm_rights cmsg = {};
	struct msghdr msg = {};
	char buf[MSG_LEN] = {};
	struct iovec iov = {};
	int ret;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = &cmsg;
	msg.msg_controllen = CMSG_SPACE(sizeof(cmsg.fd));

	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);

	/* LSM is expected to drop "Hello" with the receiver's fd */
	if (lsm_attached)
		goto no_hello;

	ret = recvmsg(receiver_fd, &msg, 0);
	if (!ASSERT_EQ(ret, MSG_LEN, "recvmsg(Hello) length") ||
	    !ASSERT_STRNEQ(buf, MSG_HELLO, MSG_LEN, "recvmsg(Hello) data"))
		return -EINVAL;

	if (!ASSERT_OK_PTR(CMSG_FIRSTHDR(&msg), "cmsg sent") ||
	    !ASSERT_EQ(cmsg.cmsghdr.cmsg_len, CMSG_LEN(sizeof(cmsg.fd)), "cmsg_len") ||
	    !ASSERT_EQ(cmsg.cmsghdr.cmsg_level, SOL_SOCKET, "cmsg_level") ||
	    !ASSERT_EQ(cmsg.cmsghdr.cmsg_type, SCM_RIGHTS, "cmsg_type"))
		return -EINVAL;

	/* Double-check if the fd is of the receiver itself. */
	receiver_fd = cmsg.fd;

	memset(buf, 0, sizeof(buf));

no_hello:
	ret = recv(receiver_fd, buf, sizeof(buf), 0);
	if (!ASSERT_EQ(ret, MSG_LEN, "recvmsg(World) length") ||
	    !ASSERT_STRNEQ(buf, MSG_WORLD, MSG_LEN, "recvmsg(World) data"))
		return -EINVAL;

	return 0;
}

static void test_scm_rights(struct lsm_unix_may_send *skel, int type)
{
	struct bpf_link *link;
	int socket_fds[2];
	int err;

	err = socketpair(AF_UNIX, type, 0, socket_fds);
	if (!ASSERT_EQ(err, 0, "socketpair"))
		return;

	err = send_fd(socket_fds[0], socket_fds[1], false);
	if (err)
		goto close;

	err = recv_fd(socket_fds[1], false);
	if (err)
		goto close;

	link = bpf_program__attach_lsm(skel->progs.unix_may_send_filter);
	if (!ASSERT_OK_PTR(link, "attach lsm"))
		goto close;

	err = send_fd(socket_fds[0], socket_fds[1], true);
	if (err)
		goto detach;

	recv_fd(socket_fds[1], true);
detach:
	err = bpf_link__destroy(link);
	ASSERT_EQ(err, 0, "detach lsm");
close:
	close(socket_fds[0]);
	close(socket_fds[1]);
}

struct sk_type {
	char name[16];
	int type;
} sk_types[] = {
	{
		.name = "SOCK_STREAM",
		.type = SOCK_STREAM,
	},
	{
		.name = "SOCK_DGRAM",
		.type = SOCK_DGRAM,
	},
	{
		.name = "SOCK_SEQPACKET",
		.type = SOCK_SEQPACKET,
	},
};

void test_lsm_unix_may_send(void)
{
	struct lsm_unix_may_send *skel;
	int i;

	skel = lsm_unix_may_send__open_and_load();
	if (!ASSERT_OK_PTR(skel, "load skel"))
		return;

	for (i = 0; i < ARRAY_SIZE(sk_types); i++)
		if (test__start_subtest(sk_types[i].name))
			test_scm_rights(skel, sk_types[i].type);

	lsm_unix_may_send__destroy(skel);
}
