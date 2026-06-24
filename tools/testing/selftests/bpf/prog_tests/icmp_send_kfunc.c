// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>
#include <linux/errqueue.h>
#include <poll.h>
#include "icmp_send.skel.h"

#define TIMEOUT_MS 1000

#define ICMP_DEST_UNREACH 3
#define ICMPV6_DEST_UNREACH 1

#define ICMP_FRAG_NEEDED 4
#define NR_ICMP_UNREACH 15
#define ICMPV6_REJECT_ROUTE 6

#define KFUNC_RET_UNSET -1

static int connect_to_fd_nonblock(int server_fd)
{
	struct sockaddr_storage addr;
	socklen_t len = sizeof(addr);
	int fd, err, on = 1;

	if (getsockname(server_fd, (struct sockaddr *)&addr, &len))
		return -1;

	fd = socket(addr.ss_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (fd < 0)
		return -1;

	if (addr.ss_family == AF_INET6 &&
	    setsockopt(fd, IPPROTO_IPV6, IPV6_RECVERR, &on, sizeof(on)) < 0) {
		close(fd);
		return -1;
	}

	err = connect(fd, (struct sockaddr *)&addr, len);
	if (err < 0 && errno != EINPROGRESS) {
		close(fd);
		return -1;
	}

	return fd;
}

static void read_icmp_errqueue(int sockfd, int expected_code, int af)
{
	int expected_ee_type = (af == AF_INET) ? ICMP_DEST_UNREACH :
						 ICMPV6_DEST_UNREACH;
	int expected_origin = (af == AF_INET) ? SO_EE_ORIGIN_ICMP :
						SO_EE_ORIGIN_ICMP6;
	int expected_level = (af == AF_INET) ? IPPROTO_IP : IPPROTO_IPV6;
	int expected_type = (af == AF_INET) ? IP_RECVERR : IPV6_RECVERR;
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
		if (cm->cmsg_level != expected_level ||
		    cm->cmsg_type != expected_type)
			continue;

		sock_err = (struct sock_extended_err *)CMSG_DATA(cm);

		if (!ASSERT_EQ(sock_err->ee_origin, expected_origin,
			       "sock_err_origin"))
			return;
		if (!ASSERT_EQ(sock_err->ee_type, expected_ee_type,
			       "sock_err_type_dest_unreach"))
			return;
		ASSERT_EQ(sock_err->ee_code, expected_code, "sock_err_code");
		return;
	}

	ASSERT_FAIL("no IP_RECVERR/IPV6_RECVERR control message found");
}

static bool valid_unreach_code(int code, int af)
{
	if (code < 0)
		return false;

	if (af == AF_INET)
		return code <= NR_ICMP_UNREACH && code != ICMP_FRAG_NEEDED;

	return code <= ICMPV6_REJECT_ROUTE;
}

static void trigger_prog_read_icmp_errqueue(struct icmp_send *skel, int code,
					    int af, const char *ip)
{
	int srv_fd = -1, client_fd = -1;
	int port;

	srv_fd = start_server(af, SOCK_STREAM, ip, 0, TIMEOUT_MS);
	if (!ASSERT_OK_FD(srv_fd, "start_server"))
		return;

	port = get_socket_local_port(srv_fd);
	if (!ASSERT_GE(port, 0, "get_socket_local_port")) {
		close(srv_fd);
		return;
	}

	skel->bss->server_port = ntohs(port);
	skel->bss->unreach_type = (af == AF_INET) ? ICMP_DEST_UNREACH :
						    ICMPV6_DEST_UNREACH;
	skel->bss->unreach_code = code;
	skel->data->kfunc_ret = KFUNC_RET_UNSET;

	client_fd = connect_to_fd_nonblock(srv_fd);
	if (!ASSERT_OK_FD(client_fd, "client_connect_nonblock")) {
		close(srv_fd);
		return;
	}

	if (valid_unreach_code(code, af))
		read_icmp_errqueue(client_fd, code, af);

	close(client_fd);
	close(srv_fd);
}

static void run_icmp_test(struct icmp_send *skel, int af, const char *ip,
			  int max_code)
{
	for (int code = 0; code <= max_code; code++) {
		if (af == AF_INET && code == ICMP_FRAG_NEEDED)
			continue;

		trigger_prog_read_icmp_errqueue(skel, code, af, ip);
		ASSERT_EQ(skel->data->kfunc_ret, 0, "kfunc_ret");
	}

	/* Test invalid codes */
	trigger_prog_read_icmp_errqueue(skel, -1, af, ip);
	ASSERT_EQ(skel->data->kfunc_ret, -EINVAL, "kfunc_ret");

	trigger_prog_read_icmp_errqueue(skel, max_code + 1, af, ip);
	ASSERT_EQ(skel->data->kfunc_ret, -EINVAL, "kfunc_ret");

	if (af == AF_INET) {
		trigger_prog_read_icmp_errqueue(skel, ICMP_FRAG_NEEDED, af, ip);
		ASSERT_EQ(skel->data->kfunc_ret, -EINVAL, "kfunc_ret");
	}
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

	if (test__start_subtest("ipv4"))
		run_icmp_test(skel, AF_INET, "127.0.0.1", NR_ICMP_UNREACH);

	if (test__start_subtest("ipv6"))
		run_icmp_test(skel, AF_INET6, "::1", ICMPV6_REJECT_ROUTE);

cleanup:
	icmp_send__destroy(skel);
	if (cgroup_fd >= 0)
		close(cgroup_fd);
}
