// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Google LLC.
// Copyright (c) 2018 Facebook

#include <test_progs.h>
#include "socket_cookie_prog.skel.h"
#include "network_helpers.h"

static int duration;

struct socket_cookie {
	__u64 cookie_key;
	__u32 cookie_value;
};

void test_socket_cookie(void)
{
	socklen_t addr_len = sizeof(struct sockaddr_in6);
	struct bpf_link *set_link, *update_link;
	int server_fd, client_fd, cgroup_fd;
	struct socket_cookie_prog *skel;
	__u32 cookie_expected_value;
	struct sockaddr_in6 addr;
	struct socket_cookie val;
	int err = 0;

	skel = socket_cookie_prog__open_and_load();
	if (CHECK(!skel, "socket_cookie_prog__open_and_load",
		  "skeleton open_and_load failed\n"))
		return;

	cgroup_fd = test__join_cgroup("/socket_cookie");
	if (CHECK(cgroup_fd < 0, "join_cgroup", "cgroup creation failed\n"))
		goto destroy_skel;

	set_link = bpf_program__attach_cgroup(skel->progs.set_cookie,
					      cgroup_fd);
	if (CHECK(IS_ERR(set_link), "set-link-cg-attach", "err %ld\n",
		  PTR_ERR(set_link)))
		goto close_cgroup_fd;

	update_link = bpf_program__attach_cgroup(skel->progs.update_cookie,
						 cgroup_fd);
	if (CHECK(IS_ERR(update_link), "update-link-cg-attach", "err %ld\n",
		  PTR_ERR(update_link)))
		goto free_set_link;

	server_fd = start_server(AF_INET6, SOCK_STREAM, "::1", 0, 0);
	if (CHECK(server_fd < 0, "start_server", "errno %d\n", errno))
		goto free_update_link;

	client_fd = connect_to_fd(server_fd, 0);
	if (CHECK(client_fd < 0, "connect_to_fd", "errno %d\n", errno))
		goto close_server_fd;

	err = bpf_map_lookup_elem(bpf_map__fd(skel->maps.socket_cookies),
				  &client_fd, &val);
	if (CHECK(err, "map_lookup", "err %d errno %d\n", err, errno))
		goto close_client_fd;

	err = getsockname(client_fd, (struct sockaddr *)&addr, &addr_len);
	if (CHECK(err, "getsockname", "Can't get client local addr\n"))
		goto close_client_fd;

	cookie_expected_value = (ntohs(addr.sin6_port) << 8) | 0xFF;
	CHECK(val.cookie_value != cookie_expected_value, "",
	      "Unexpected value in map: %x != %x\n", val.cookie_value,
	      cookie_expected_value);

close_client_fd:
	close(client_fd);
close_server_fd:
	close(server_fd);
free_update_link:
	bpf_link__destroy(update_link);
free_set_link:
	bpf_link__destroy(set_link);
close_cgroup_fd:
	close(cgroup_fd);
destroy_skel:
	socket_cookie_prog__destroy(skel);
}
