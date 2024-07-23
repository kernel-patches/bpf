/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2021 Hengqi Chen */

#include <test_progs.h>
#include <sys/un.h>
#include "test_skc_to_unix_sock.skel.h"
#include "network_helpers.h"

static const char *sock_path = "@skc_to_unix_sock";

void test_skc_to_unix_sock(void)
{
	struct network_helper_opts opts = {
		.backlog = 1,
	};
	struct test_skc_to_unix_sock *skel;
	int err, sockfd = 0;

	skel = test_skc_to_unix_sock__open();
	if (!ASSERT_OK_PTR(skel, "could not open BPF object"))
		return;

	skel->rodata->my_pid = getpid();

	err = test_skc_to_unix_sock__load(skel);
	if (!ASSERT_OK(err, "could not load BPF object"))
		goto cleanup;

	err = test_skc_to_unix_sock__attach(skel);
	if (!ASSERT_OK(err, "could not attach BPF object"))
		goto cleanup;

	/* trigger unix_listen */
	sockfd = start_server_str(AF_UNIX, SOCK_STREAM, sock_path + 1, 0, &opts);
	if (!ASSERT_OK_FD(sockfd, "start_server_str"))
		goto cleanup;

	ASSERT_EQ(strcmp(skel->bss->path, sock_path), 0, "bpf_skc_to_unix_sock failed");

cleanup:
	if (sockfd)
		close(sockfd);
	test_skc_to_unix_sock__destroy(skel);
}
