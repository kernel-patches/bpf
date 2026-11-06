// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "network_helpers.h"
#include "struct_ops_vmlinux.lskel.h"
#include "struct_ops_mod.lskel.h"

static int set_tcp_ca_cb(int fd, void *opts)
{
	const char *tcp_ca = opts;

	if (!ASSERT_OK(setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION,
				  tcp_ca, strlen(tcp_ca)), "setsockopt"))
		return -1;
	return 0;
}

static void test_vmlinux(void)
{
	char tcp_ca[] = "bpf_lskel_ca";
	struct network_helper_opts opts = {
		.post_socket_cb	= set_tcp_ca_cb,
		.cb_opts	= tcp_ca,
	};
	struct struct_ops_vmlinux_lskel *skel;
	int srv_fd = -1, cli_fd = -1, sock_fd = -1;
	int err;

	skel = struct_ops_vmlinux_lskel__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	err = struct_ops_vmlinux_lskel__attach(skel);
	if (!ASSERT_OK(err, "attach"))
		goto cleanup;

	srv_fd = start_server_str(AF_INET6, SOCK_STREAM, NULL, 0, &opts);
	if (!ASSERT_NEQ(srv_fd, -1, "start_server_str"))
		goto cleanup;

	cli_fd = connect_to_fd_opts(srv_fd, &opts);
	if (!ASSERT_NEQ(cli_fd, -1, "connect_to_fd_opts"))
		goto cleanup;

	ASSERT_GT(skel->bss->ca_init_cnt, 0, "ca_init_cnt");

	close(cli_fd);
	cli_fd = -1;
	close(srv_fd);
	srv_fd = -1;

	struct_ops_vmlinux_lskel__detach(skel);
	skel->links.lskel_ca_fd = 0;

	/* Verify congestion control was unregistered on detach */
	sock_fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (!ASSERT_GE(sock_fd, 0, "socket"))
		goto cleanup;

	err = setsockopt(sock_fd, IPPROTO_TCP, TCP_CONGESTION,
			 tcp_ca, strlen(tcp_ca));
	ASSERT_EQ(err, -1, "setsockopt_after_detach");
	ASSERT_EQ(errno, ENOENT, "errno_after_detach");

cleanup:
	if (sock_fd != -1)
		close(sock_fd);
	if (cli_fd != -1)
		close(cli_fd);
	if (srv_fd != -1)
		close(srv_fd);
	struct_ops_vmlinux_lskel__destroy(skel);
}

static void test_module(void)
{
	struct struct_ops_mod_lskel *skel;
	int err, link_fd;

	if (!env.has_testmod) {
		test__skip();
		return;
	}

	skel = struct_ops_mod_lskel__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	err = struct_ops_mod_lskel__attach(skel);
	if (!ASSERT_OK(err, "attach"))
		goto cleanup;

	ASSERT_GT(skel->links.testmod_1_fd, 0, "testmod_1_fd");
	ASSERT_GT(skel->links.testmod_2_fd, 0, "testmod_2_fd");
	ASSERT_EQ(skel->bss->test_1_cnt, 2, "test_1_cnt");
	ASSERT_EQ(skel->bss->testmod_1_result, 17, "testmod_1_result");
	ASSERT_EQ(skel->bss->testmod_2_result, 28, "testmod_2_result");

	struct_ops_mod_lskel__detach(skel);
	skel->links.testmod_1_fd = 0;
	skel->links.testmod_2_fd = 0;
	memset(skel->bss, 0, sizeof(*skel->bss));

	link_fd = struct_ops_mod_lskel__testmod_1__attach(skel);
	if (!ASSERT_GT(link_fd, 0, "testmod_1_attach"))
		goto cleanup;

	ASSERT_EQ(skel->bss->test_1_cnt, 1, "reattach_test_1_cnt");
	ASSERT_EQ(skel->bss->testmod_1_result, 17, "reattach_testmod_1_result");
	ASSERT_EQ(skel->bss->testmod_2_result, 0, "reattach_testmod_2_result");

cleanup:
	struct_ops_mod_lskel__destroy(skel);
}

void test_struct_ops_lskel(void)
{
	if (test__start_subtest("vmlinux"))
		test_vmlinux();
	if (test__start_subtest("module"))
		test_module();
}
