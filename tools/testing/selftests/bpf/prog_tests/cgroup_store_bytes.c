// SPDX-License-Identifier: GPL-2.0-only

#include <test_progs.h>
#include <network_helpers.h>

#include "cgroup_store_bytes.skel.h"

void test_cgroup_store_bytes(void)
{
	int server_fd, cgroup_fd, client_fd, err, bytes;
	struct sockaddr server_addr;
	socklen_t addrlen = sizeof(server_addr);
	char buf[] = "testing";
	struct sockaddr_storage ss;
	socklen_t slen = sizeof(ss);
	char recv_buf[BUFSIZ];
	struct in_addr addr;
	unsigned short port;
	struct cgroup_store_bytes *skel;

	cgroup_fd = test__join_cgroup("/cgroup_store_bytes");
	if (!ASSERT_GE(cgroup_fd, 0, "cgroup_fd"))
		return;

	skel = cgroup_store_bytes__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel"))
		goto close_cgroup_fd;

	skel->links.cgroup_store_bytes = bpf_program__attach_cgroup(
			skel->progs.cgroup_store_bytes, cgroup_fd);
	if (!ASSERT_OK_PTR(skel->links.cgroup_store_bytes , "cgroup_store_bytes"))
		goto close_skeleton;

	server_fd = start_server(AF_INET, SOCK_DGRAM, NULL, 0, 0);
	if (!ASSERT_GE(server_fd, 0, "server_fd"))
		goto close_skeleton;

	client_fd = start_server(AF_INET, SOCK_DGRAM, NULL, 0, 0);
	if (!ASSERT_GE(client_fd, 0, "client_fd"))
		goto close_server_fd;

	err = getsockname(server_fd, &server_addr, &addrlen);
	if (!ASSERT_OK(err, "getsockname"))
		goto close_client_fd;

	bytes = sendto(client_fd, buf, sizeof(buf), 0, &server_addr,
			sizeof(server_addr));
	if (!ASSERT_EQ(bytes, sizeof(buf), "sendto"))
		goto close_client_fd;

	bytes = recvfrom(server_fd, &recv_buf, sizeof(recv_buf), 0,
			(struct sockaddr *)&ss, &slen);
	if (!ASSERT_GE(bytes, 0, "recvfrom"))
		goto close_client_fd;

	addr = ((struct sockaddr_in *)&ss)->sin_addr;

	ASSERT_EQ(skel->bss->test_result, 1, "bpf program returned failure");
	port = ((struct sockaddr_in *)&ss)->sin_port;
	ASSERT_EQ(port, 5555, "bpf program failed to change port");

close_client_fd:
	close(client_fd);
close_server_fd:
	close(server_fd);
close_skeleton:
	cgroup_store_bytes__destroy(skel);
close_cgroup_fd:
	close(cgroup_fd);
}
