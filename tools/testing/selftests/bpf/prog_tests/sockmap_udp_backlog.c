// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 KylinSoft */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "test_progs.h"
#include "test_sockmap_udp_backlog.skel.h"

#define RCV_TIMEOUT_MS	1000
#define HANG_LIMIT_MS	5000

static int run_child(void)
{
	struct test_sockmap_udp_backlog *skel;
	struct timeval tv = { .tv_sec = RCV_TIMEOUT_MS / 1000 };
	struct sockaddr_in addr = {};
	struct timespec t0, t1;
	socklen_t addrlen = sizeof(addr);
	int zero = 0, sfd, ret, err, exit_code = 1;
	double elapsed_ms;
	char byte = 0;

	skel = test_sockmap_udp_backlog__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return 1;

	sfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (!ASSERT_GE(sfd, 0, "socket"))
		goto out;

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;
	if (!ASSERT_OK(bind(sfd, (struct sockaddr *)&addr, sizeof(addr)), "bind"))
		goto close;
	addrlen = sizeof(addr);
	if (!ASSERT_OK(getsockname(sfd, (struct sockaddr *)&addr, &addrlen),
		       "getsockname"))
		goto close;

	/* Non-TCP redirect targets need TCP_ESTABLISHED: connect to self. */
	if (!ASSERT_OK(connect(sfd, (struct sockaddr *)&addr, sizeof(addr)),
		       "connect"))
		goto close;

	err = bpf_prog_attach(bpf_program__fd(skel->progs.redir_to_self),
			      bpf_map__fd(skel->maps.sock_map),
			      BPF_SK_SKB_VERDICT, 0);
	if (!ASSERT_OK(err, "prog_attach"))
		goto close;

	err = bpf_map_update_elem(bpf_map__fd(skel->maps.sock_map),
				  &zero, &sfd, BPF_ANY);
	if (!ASSERT_OK(err, "map_update"))
		goto close;

	if (!ASSERT_EQ(send(sfd, &byte, 1, 0), 1, "send"))
		goto close;

	/* Let the backlog pick the skb up. */
	usleep(100 * 1000);

	err = setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	if (!ASSERT_OK(err, "set_rcvtimeo"))
		goto close;

	/* A re-sent copy may be read back; the reader must not spin. */
	clock_gettime(CLOCK_MONOTONIC, &t0);
	errno = 0;
	ret = recv(sfd, &byte, 1, 0);
	clock_gettime(CLOCK_MONOTONIC, &t1);
	elapsed_ms = (t1.tv_sec - t0.tv_sec) * 1000.0 +
		     (t1.tv_nsec - t0.tv_nsec) / 1000000.0;

	if (ret != 1) {
		if (!ASSERT_EQ(ret, -1, "recv"))
			goto close;
		if (!ASSERT_EQ(errno, EAGAIN, "recv_errno"))
			goto close;
		if (!ASSERT_GE(elapsed_ms, RCV_TIMEOUT_MS * 0.9, "recv_blocked"))
			goto close;
		if (!ASSERT_LT(elapsed_ms, HANG_LIMIT_MS, "recv_timely"))
			goto close;
	}

	exit_code = 0;
close:
	close(sfd);
out:
	test_sockmap_udp_backlog__destroy(skel);
	return exit_code;
}

void serial_test_sockmap_udp_backlog(void)
{
	pid_t pid;
	int status = 0;
	int i;

	pid = fork();
	if (!ASSERT_GE(pid, 0, "fork"))
		return;

	if (pid == 0)
		_exit(run_child());

	/* The child may survive SIGKILL: only a bounded wait is safe. */
	for (i = 0; i < HANG_LIMIT_MS / 100; i++) {
		if (waitpid(pid, &status, WNOHANG) == pid)
			break;
		usleep(100 * 1000);
	}

	if (i == HANG_LIMIT_MS / 100) {
		kill(pid, SIGKILL);
		for (i = 0; i < 10; i++) {
			if (waitpid(pid, &status, WNOHANG) == pid)
				break;
			usleep(100 * 1000);
		}
		fprintf(stderr,
			"udp_bpf_recvmsg() spins on backlog-only ingress (timeout %dms)\n",
			HANG_LIMIT_MS);
		test__fail();
		return;
	}

	if (WIFEXITED(status)) {
		ASSERT_EQ(WEXITSTATUS(status), 0, "child_exit_code");
	} else {
		fprintf(stderr, "child terminated abnormally (status=%d)\n", status);
		test__fail();
	}
}
