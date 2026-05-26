// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>
#include <linux/errqueue.h>
#include <poll.h>
#include "icmp_send.skel.h"

#define TIMEOUT_MS 1000

#define ICMP_DEST_UNREACH 3

#define ICMP_FRAG_NEEDED 4
#define NR_ICMP_UNREACH 15

static int connect_to_fd_nonblock(int server_fd)
{
	struct sockaddr_storage addr;
	socklen_t len = sizeof(addr);
	int fd, err;

	if (getsockname(server_fd, (struct sockaddr *)&addr, &len))
		return -1;

	fd = socket(addr.ss_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (fd < 0)
		return -1;

	err = connect(fd, (struct sockaddr *)&addr, len);
	if (err < 0 && errno != EINPROGRESS) {
		close(fd);
		return -1;
	}

	return fd;
}

static void read_icmp_errqueue(int sockfd, int expected_code)
{
	struct sock_extended_err *sock_err;
	char ctrl_buf[512];
	struct msghdr msg = {
		.msg_control = ctrl_buf,
		.msg_controllen = sizeof(ctrl_buf),
	};
	struct pollfd pfd = {
		.fd = sockfd,
		.events = POLLERR,
	};
	struct cmsghdr *cm;
	ssize_t n;

	if (!ASSERT_GE(poll(&pfd, 1, TIMEOUT_MS), 1, "poll_errqueue"))
		return;

	n = recvmsg(sockfd, &msg, MSG_ERRQUEUE);
	if (!ASSERT_GE(n, 0, "recvmsg_errqueue"))
		return;

	cm = CMSG_FIRSTHDR(&msg);
	if (!ASSERT_NEQ(cm, NULL, "cm_firsthdr_null"))
		return;

	for (; cm; cm = CMSG_NXTHDR(&msg, cm)) {
		if (cm->cmsg_level != IPPROTO_IP || cm->cmsg_type != IP_RECVERR)
			continue;

		sock_err = (struct sock_extended_err *)CMSG_DATA(cm);

		if (!ASSERT_EQ(sock_err->ee_origin, SO_EE_ORIGIN_ICMP,
			       "sock_err_origin_icmp"))
			return;
		if (!ASSERT_EQ(sock_err->ee_type, ICMP_DEST_UNREACH,
			       "sock_err_type_dest_unreach"))
			return;
		ASSERT_EQ(sock_err->ee_code, expected_code, "sock_err_code");
		return;
	}

	ASSERT_FAIL("no IP_RECVERR/IPV6_RECVERR control message found");
}

static void trigger_prog_read_icmp_errqueue(struct icmp_send *skel, int code)
{
	int srv_fd = -1, client_fd = -1;
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);

	srv_fd = start_server(AF_INET, SOCK_STREAM, "127.0.0.1", 0, TIMEOUT_MS);
	if (!ASSERT_GE(srv_fd, 0, "start_server"))
		return;

	if (getsockname(srv_fd, (struct sockaddr *)&addr, &len)) {
		close(srv_fd);
		return;
	}
	skel->bss->server_port = ntohs(addr.sin_port);
	skel->bss->unreach_code = code;

	client_fd = connect_to_fd_nonblock(srv_fd);
	if (!ASSERT_OK_FD(client_fd, "client_connect_nonblock")) {
		close(srv_fd);
		return;
	}

	/* Skip reading ICMP error queue if code is invalid */
	if (code >= 0 && code <= NR_ICMP_UNREACH)
		read_icmp_errqueue(client_fd, code);

	close(client_fd);
	close(srv_fd);
}

void test_icmp_send_unreach_cgroup(void)
{
	struct icmp_send *skel;
	int cgroup_fd = -1;

	skel = icmp_send__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		goto cleanup;

	cgroup_fd = test__join_cgroup("/icmp_send_unreach_cgroup");
	if (!ASSERT_OK_FD(cgroup_fd, "join_cgroup"))
		goto cleanup;

	skel->links.egress =
		bpf_program__attach_cgroup(skel->progs.egress, cgroup_fd);
	if (!ASSERT_OK_PTR(skel->links.egress, "prog_attach_cgroup"))
		goto cleanup;

	for (int code = 0; code <= NR_ICMP_UNREACH; code++) {
		/* The TCP stack reacts differently when asking for
		 * fragmentation, let's ignore it for now.
		 */
		if (code == ICMP_FRAG_NEEDED)
			continue;

		trigger_prog_read_icmp_errqueue(skel, code);
		ASSERT_EQ(skel->data->kfunc_ret, 0, "kfunc_ret");
	}

	/* Test an invalid code */
	trigger_prog_read_icmp_errqueue(skel, -1);
	ASSERT_EQ(skel->data->kfunc_ret, -EINVAL, "kfunc_ret");

cleanup:
	icmp_send__destroy(skel);
	close(cgroup_fd);
}
