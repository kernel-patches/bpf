// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "cgroup_helpers.h"
#include "network_helpers.h"
#include "sock_ops_get_sk.skel.h"

/*
 * Test that reading ctx->sk with dst_reg == src_reg in a sock_ops program
 * correctly returns NULL when is_fullsock == 0 (TCP_NEW_SYN_RECV state).
 *
 * The bug was in SOCK_OPS_GET_SK() macro which failed to zero the destination
 * register when it was the same as the source register and the socket was not
 * a full socket. This left the ctx pointer in the register, which then passed
 * the NULL check and could be used as a socket pointer, causing OOB access.
 */
void test_sock_ops_get_sk(void)
{
	struct sock_ops_get_sk *skel;
	int cgroup_fd, server_fd, client_fd;
	int prog_fd, err;

	cgroup_fd = test__join_cgroup("/sock_ops_get_sk");
	if (!ASSERT_GE(cgroup_fd, 0, "join_cgroup"))
		return;

	skel = sock_ops_get_sk__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_load"))
		goto close_cgroup;

	prog_fd = bpf_program__fd(skel->progs.sock_ops_get_sk_same_reg);
	err = bpf_prog_attach(prog_fd, cgroup_fd, BPF_CGROUP_SOCK_OPS, 0);
	if (!ASSERT_OK(err, "prog_attach"))
		goto destroy_skel;

	server_fd = start_server(AF_INET, SOCK_STREAM, NULL, 0, 0);
	if (!ASSERT_GE(server_fd, 0, "start_server"))
		goto detach;

	/* Trigger TCP handshake which causes TCP_NEW_SYN_RECV state where
	 * is_fullsock == 0. With the bug, ctx->sk loaded with same src/dst
	 * register would return a stale ctx pointer instead of NULL.
	 */
	client_fd = connect_to_fd(server_fd, 0);
	if (!ASSERT_GE(client_fd, 0, "connect_to_fd"))
		goto close_server;

	close(client_fd);

	/* Verify that the is_fullsock == 0 path was hit and sk was NULL */
	ASSERT_EQ(skel->bss->null_seen, 1, "null_seen");
	ASSERT_EQ(skel->bss->bug_detected, 0, "bug_not_detected");

close_server:
	close(server_fd);
detach:
	bpf_prog_detach(cgroup_fd, BPF_CGROUP_SOCK_OPS);
destroy_skel:
	sock_ops_get_sk__destroy(skel);
close_cgroup:
	close(cgroup_fd);
}
