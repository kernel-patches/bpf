// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "cgroup_helpers.h"
#include "network_helpers.h"
#include "connect_force_port4.skel.h"
#include "connect_force_port6.skel.h"

static int verify_ports(int family, int fd,
			__u16 expected_local, __u16 expected_peer)
{
	struct sockaddr_storage addr;
	socklen_t len = sizeof(addr);
	__u16 port;

	if (getsockname(fd, (struct sockaddr *)&addr, &len)) {
		log_err("Failed to get server addr");
		return -1;
	}

	if (family == AF_INET)
		port = ((struct sockaddr_in *)&addr)->sin_port;
	else
		port = ((struct sockaddr_in6 *)&addr)->sin6_port;

	if (ntohs(port) != expected_local) {
		log_err("Unexpected local port %d, expected %d", ntohs(port),
			expected_local);
		return -1;
	}

	if (getpeername(fd, (struct sockaddr *)&addr, &len)) {
		log_err("Failed to get peer addr");
		return -1;
	}

	if (family == AF_INET)
		port = ((struct sockaddr_in *)&addr)->sin_port;
	else
		port = ((struct sockaddr_in6 *)&addr)->sin6_port;

	if (ntohs(port) != expected_peer) {
		log_err("Unexpected peer port %d, expected %d", ntohs(port),
			expected_peer);
		return -1;
	}

	return 0;
}

static int attach_progs(int cgroup_fd, int family,
			int connect_fd, int getpeername_fd,
			int getsockname_fd)
{
	bool v4 = family == AF_INET;
	int err;

	err = bpf_prog_attach(connect_fd, cgroup_fd,
			      v4 ? BPF_CGROUP_INET4_CONNECT :
				   BPF_CGROUP_INET6_CONNECT, 0);
	if (!ASSERT_OK(err, "attach connect"))
		return -1;

	err = bpf_prog_attach(getpeername_fd, cgroup_fd,
			      v4 ? BPF_CGROUP_INET4_GETPEERNAME :
				   BPF_CGROUP_INET6_GETPEERNAME, 0);
	if (!ASSERT_OK(err, "attach getpeername"))
		return -1;

	err = bpf_prog_attach(getsockname_fd, cgroup_fd,
			      v4 ? BPF_CGROUP_INET4_GETSOCKNAME :
				   BPF_CGROUP_INET6_GETSOCKNAME, 0);
	if (!ASSERT_OK(err, "attach getsockname"))
		return -1;

	return 0;
}

static int run_tests(int cgroup_fd, int family, unsigned short *bss_port)
{
	int types[] = {SOCK_STREAM, SOCK_DGRAM};
	bool v4 = family == AF_INET;
	__u16 expected_local_port = v4 ? 22222 : 22223;
	__u16 expected_peer_port = 60000;
	int server_fd, port, fd, i;

	for (i = 0; i < ARRAY_SIZE(types); i++) {
		/* Log the socket type to identify which test is running. */
		server_fd = start_server(family, types[i], NULL, 0, 0);
		if (!ASSERT_GE(server_fd, 0,
			       types[i] == SOCK_STREAM ? "start_server tcp" :
							 "start_server udp"))
			return -1;

		port = get_socket_local_port(server_fd);
		if (!ASSERT_GE(port, 0, "get_socket_local_port")) {
			close(server_fd);
			return -1;
		}
		*bss_port = ntohs(port);

		fd = connect_to_fd(server_fd, 0);
		if (!ASSERT_GE(fd, 0, "connect_to_fd")) {
			close(server_fd);
			return -1;
		}

		ASSERT_OK(verify_ports(family, fd, expected_local_port,
				       expected_peer_port), "verify_ports");
		close(fd);
		close(server_fd);
	}

	return 0;
}

static void test_v4(int cgroup_fd)
{
	struct connect_force_port4 *skel;

	skel = connect_force_port4__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel4_open_and_load"))
		return;

	if (attach_progs(cgroup_fd, AF_INET,
			 bpf_program__fd(skel->progs.connect4),
			 bpf_program__fd(skel->progs.getpeername4),
			 bpf_program__fd(skel->progs.getsockname4)))
		goto out;

	run_tests(cgroup_fd, AF_INET, &skel->bss->port);

out:
	connect_force_port4__destroy(skel);
}

static void test_v6(int cgroup_fd)
{
	struct connect_force_port6 *skel;

	skel = connect_force_port6__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel6_open_and_load"))
		return;

	if (attach_progs(cgroup_fd, AF_INET6,
			 bpf_program__fd(skel->progs.connect6),
			 bpf_program__fd(skel->progs.getpeername6),
			 bpf_program__fd(skel->progs.getsockname6)))
		goto out;

	run_tests(cgroup_fd, AF_INET6, &skel->bss->port);

out:
	connect_force_port6__destroy(skel);
}

void test_connect_force_port(void)
{
	int cgroup_fd;

	cgroup_fd = test__join_cgroup("/connect_force_port");
	if (CHECK_FAIL(cgroup_fd < 0))
		return;

	test_v4(cgroup_fd);
	test_v6(cgroup_fd);

	close(cgroup_fd);
}
