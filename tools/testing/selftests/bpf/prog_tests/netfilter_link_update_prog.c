// SPDX-License-Identifier: GPL-2.0-or-later

#include <test_progs.h>
#include <linux/netfilter.h>
#include <network_helpers.h>
#include "test_netfilter_link_update_prog.skel.h"

#define SERVER_ADDR "127.0.0.1"
#define SERVER_PORT 12345

static const char dummy_message[] = "A dummy message";

static int send_dummy(int client_fd)
{
	struct sockaddr_storage saddr;
	struct sockaddr *saddr_p;
	socklen_t saddr_len;
	int err;

	saddr_p = (struct sockaddr *)&saddr;
	err = make_sockaddr(AF_INET, SERVER_ADDR, SERVER_PORT, &saddr, &saddr_len);
	if (!ASSERT_OK(err, "make_sockaddr"))
		return -1;

	err = sendto(client_fd, dummy_message, sizeof(dummy_message) - 1, 0, saddr_p, saddr_len);
	if (!ASSERT_GE(err, 0, "sendto"))
		return -1;

	return 0;
}

void test_netfilter_link_update_prog(void)
{
	LIBBPF_OPTS(bpf_netfilter_opts, opts,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = 100);
	struct test_netfilter_link_update_prog *skel;
	struct bpf_program *prog;
	int server_fd, client_fd;
	int err;

	skel = test_netfilter_link_update_prog__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_netfilter_link_update_prog__open_and_load"))
		goto out;

	prog = skel->progs.nf_link_prog;

	if (!ASSERT_OK_PTR(prog, "load program"))
		goto out;

	skel->links.nf_link_prog = bpf_program__attach_netfilter(prog, &opts);
	if (!ASSERT_OK_PTR(skel->links.nf_link_prog, "attach netfilter program"))
		goto out;

	server_fd = start_server(AF_INET, SOCK_DGRAM, SERVER_ADDR, SERVER_PORT, 0);
	if (!ASSERT_GE(server_fd, 0, "start_server"))
		goto out;

	client_fd = connect_to_fd(server_fd, 0);
	if (!ASSERT_GE(client_fd, 0, "connect_to_fd"))
		goto out;

	send_dummy(client_fd);

	ASSERT_EQ(skel->bss->counter, 0, "counter should be zero");

	err = bpf_link__update_program(skel->links.nf_link_prog, skel->progs.nf_link_prog_new);
	if (!ASSERT_OK(err, "bpf_link__update_program"))
		goto out;

	send_dummy(client_fd);
	ASSERT_GE(skel->bss->counter, 0, "counter should be greater than zero");
out:
	if (client_fd > 0)
		close(client_fd);
	if (server_fd > 0)
		close(server_fd);

	test_netfilter_link_update_prog__destroy(skel);
}


