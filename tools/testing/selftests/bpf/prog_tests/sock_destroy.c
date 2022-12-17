// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>

#include "sock_destroy_prog.skel.h"
#include "network_helpers.h"

#define ECONNABORTED 103

static int duration;

static void start_iter_sockets(struct bpf_program *prog)
{
	struct bpf_link *link;
	char buf[16] = {};
	int iter_fd, len;

	link = bpf_program__attach_iter(prog, NULL);
	if (!ASSERT_OK_PTR(link, "attach_iter"))
		return;

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (!ASSERT_GE(iter_fd, 0, "create_iter"))
		goto free_link;

	while ((len = read(iter_fd, buf, sizeof(buf))) > 0)
		;
	CHECK(len < 0, "read", "read failed: %s\n", strerror(errno));

	close(iter_fd);

free_link:
	bpf_link__destroy(link);
}

void test_tcp(struct sock_destroy_prog *skel)
{
	int serv = -1, clien = -1, n = 0;

	serv = start_server(AF_INET6, SOCK_STREAM, NULL, 0, 0);
	if (CHECK(serv < 0, "start_server", "failed to start server\n"))
		goto cleanup_serv;

	clien = connect_to_fd(serv, 0);
	if (CHECK(clien < 0, "connect_to_fd", "errno %d\n", errno))
		goto cleanup_serv;

	serv = accept(serv, NULL, NULL);
	if (CHECK(serv < 0, "accept", "errno %d\n", errno))
		goto cleanup;

	n = send(clien, "t", 1, 0);
	if (CHECK(n < 0, "client_send", "client failed to send on socket\n"))
		goto cleanup;

	start_iter_sockets(skel->progs.iter_tcp6);

	// Sockets are destroyed asynchronously.
	usleep(1000);
	n = send(clien, "t", 1, 0);

	if (CHECK(n > 0, "client_send", "succeeded on destroyed socket\n"))
		goto cleanup;
	CHECK(errno != ECONNABORTED, "client_send", "unexpected error code on destroyed socket\n");


cleanup:
	close(clien);
cleanup_serv:
	close(serv);
}


void test_udp(struct sock_destroy_prog *skel)
{
	int serv = -1, clien = -1, n = 0;

	serv = start_server(AF_INET6, SOCK_DGRAM, NULL, 0, 0);
	if (CHECK(serv < 0, "start_server", "failed to start server\n"))
		goto cleanup_serv;

	clien = connect_to_fd(serv, 0);
	if (CHECK(clien < 0, "connect_to_fd", "errno %d\n", errno))
		goto cleanup_serv;

	n = send(clien, "t", 1, 0);
	if (CHECK(n < 0, "client_send", "client failed to send on socket\n"))
		goto cleanup;

	start_iter_sockets(skel->progs.iter_udp6);

	// Sockets are destroyed asynchronously.
	usleep(1000);

	n = send(clien, "t", 1, 0);
	if (CHECK(n > 0, "client_send", "succeeded on destroyed socket\n"))
		goto cleanup;
	// UDP sockets have an overriding error code after they are disconnected.


cleanup:
	close(clien);
cleanup_serv:
	close(serv);
}

void test_sock_destroy(void)
{
	int cgroup_fd = 0;
	struct sock_destroy_prog *skel;

	skel = sock_destroy_prog__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	cgroup_fd = test__join_cgroup("/sock_destroy");
	if (CHECK(cgroup_fd < 0, "join_cgroup", "cgroup creation failed\n"))
		goto close_cgroup_fd;

	skel->links.sock_connect = bpf_program__attach_cgroup(
		skel->progs.sock_connect, cgroup_fd);
	if (!ASSERT_OK_PTR(skel->links.sock_connect, "prog_attach"))
		goto close_cgroup_fd;

	test_tcp(skel);
	test_udp(skel);


close_cgroup_fd:
	close(cgroup_fd);
	sock_destroy_prog__destroy(skel);
}
