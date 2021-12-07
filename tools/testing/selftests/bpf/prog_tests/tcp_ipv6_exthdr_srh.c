// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <linux/seg6.h>
#include "cgroup_helpers.h"
#include "network_helpers.h"

struct tcp_srh_storage {
	struct in6_addr inner_segment;
};

static void send_byte(int fd)
{
	char b = 0x55;

	if (CHECK_FAIL(send(fd, &b, sizeof(b), 0) != 1))
		perror("Failed to send single byte");
}

static int verify_srh(int map_fd, int server_fd, struct ipv6_sr_hdr *client_srh)
{
	int err = 0;
	struct tcp_srh_storage val;

	if (CHECK_FAIL(bpf_map_lookup_elem(map_fd, &server_fd, &val) < 0)) {
		perror("Failed to read socket storage");
		return -1;
	}

	if (memcmp(&val.inner_segment, &client_srh->segments[1],
		   sizeof(struct in6_addr))) {
		log_err("The inner segment of the received SRH differs from the sent one");
		err++;
	}

	return err;
}

static int run_test(int cgroup_fd, int listen_fd)
{
	struct bpf_prog_load_attr attr = {
		.prog_type = BPF_PROG_TYPE_SOCK_OPS,
		.file = "./tcp_ipv6_exthdr_srh.o",
		.expected_attach_type = BPF_CGROUP_SOCK_OPS,
	};
	size_t srh_size = sizeof(struct ipv6_sr_hdr) +
		2 * sizeof(struct in6_addr);
	struct ipv6_sr_hdr *client_srh;
	struct bpf_object *obj;
	struct bpf_map *map;
	struct timeval tv;
	int client_fd;
	int server_fd;
	int prog_fd;
	int map_fd;
	char byte;
	int err;

	err = bpf_prog_load_xattr(&attr, &obj, &prog_fd);
	if (err) {
		log_err("Failed to load BPF object");
		return -1;
	}

	map = bpf_object__next_map(obj, NULL);
	map_fd = bpf_map__fd(map);

	err = bpf_prog_attach(prog_fd, cgroup_fd, BPF_CGROUP_SOCK_OPS, 0);
	if (err) {
		log_err("Failed to attach BPF program");
		goto close_bpf_object;
	}

	client_fd = connect_to_fd(listen_fd, 0);
	if (client_fd < 0) {
		err = -1;
		goto close_bpf_object;
	}

	server_fd = accept(listen_fd, NULL, 0);
	if (server_fd < 0) {
		err = -1;
		goto close_client_fd;
	}

	/* Set an SRH with ::1 as an intermediate segment on the client */

	client_srh = calloc(1, srh_size);
	if (!client_srh) {
		log_err("Failed to create the SRH to send");
		goto close_server_fd;
	}
	client_srh->type = IPV6_SRCRT_TYPE_4;
	// We do not count the first 8 bytes (RFC 8200 Section 4.4)
	client_srh->hdrlen = (2 * sizeof(struct in6_addr)) >> 3;
	client_srh->segments_left = 1;
	client_srh->first_segment = 1;
	// client_srh->segments[0] is set by the kernel
	memcpy(&client_srh->segments[1], &in6addr_loopback,
	       sizeof(struct in6_addr));

	if (setsockopt(client_fd, SOL_IPV6, IPV6_RTHDR, client_srh,
		       srh_size)) {
		log_err("Failed to set the SRH on the client");
		goto free_srh;
	}

	/* Send traffic with this SRH
	 * and check its parsing on the server side
	 */

	tv.tv_sec = 1;
	tv.tv_usec = 0;
	if (setsockopt(server_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv,
		       sizeof(tv))) {
		log_err("Failed to set the receive timeout on the server");
		err = -1;
		goto free_srh;
	}

	send_byte(client_fd);
	if (recv(server_fd, &byte, 1, 0) != 1) {
		log_err("Failed to get the byte under one second on the server 2");
		err = -1;
		goto free_srh;
	}

	err += verify_srh(map_fd, server_fd, client_srh);

free_srh:
	free(client_srh);
close_server_fd:
	close(server_fd);
close_client_fd:
	close(client_fd);
close_bpf_object:
	bpf_object__close(obj);
	return err;
}

void test_tcp_ipv6_exthdr_srh(void)
{
	int server_fd, cgroup_fd;

	cgroup_fd = test__join_cgroup("/tcp_ipv6_exthdr_srh");
	if (CHECK_FAIL(cgroup_fd < 0))
		return;

	server_fd = start_server(AF_INET6, SOCK_STREAM, "::1", 0, 0);
	if (CHECK_FAIL(server_fd < 0))
		goto close_cgroup_fd;

	if (CHECK_FAIL(system("sysctl net.ipv6.conf.all.seg6_enabled=1")))
		goto close_server;

	if (CHECK_FAIL(system("sysctl net.ipv6.conf.lo.seg6_enabled=1")))
		goto reset_sysctl;

	CHECK_FAIL(run_test(cgroup_fd, server_fd));

	if (CHECK_FAIL(system("sysctl net.ipv6.conf.lo.seg6_enabled=0")))
		log_err("Cannot reset sysctl net.ipv6.conf.lo.seg6_enabled to 0");

reset_sysctl:
	if (CHECK_FAIL(system("sysctl net.ipv6.conf.all.seg6_enabled=0")))
		log_err("Cannot reset sysctl net.ipv6.conf.all.seg6_enabled to 0");

close_server:
	close(server_fd);
close_cgroup_fd:
	close(cgroup_fd);
}
