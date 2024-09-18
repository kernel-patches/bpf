// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright 2024 Bytedance.
 */

#include <test_progs.h>

#include "cg_skb_get_classid.skel.h"

#include "cgroup_helpers.h"
#include "network_helpers.h"

static int run_test(int cgroup_fd, int server_fd)
{
	struct cg_skb_get_classid *skel;
	int fd, err = 0;

	skel = cg_skb_get_classid__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return -1;

	skel->links.cg_skb_classid =
		bpf_program__attach_cgroup(skel->progs.cg_skb_classid,
					   cgroup_fd);
	if (!ASSERT_OK_PTR(skel->links.cg_skb_classid, "prog_attach")) {
		err = -1;
		goto out;
	}

	if (!ASSERT_OK(join_classid(), "join_classid")) {
		err = -1;
		goto out;
	}

	errno = 0;
	fd = connect_to_fd_opts(server_fd, NULL);
	if (fd >= 0) {
		if (skel->bss->classid != getpid()) {
			log_err("Get unexpected classid");
			err = -1;
		}

		close(fd);
	} else {
		log_err("Unexpected errno from connect to server");
		err = -1;
	}
out:
	cg_skb_get_classid__destroy(skel);
	return err;
}

void test_cg_skb_get_classid(void)
{
	struct network_helper_opts opts = {};
	int server_fd, client_fd, cgroup_fd;
	static const int port = 60120;

	/* Step 1: Check base connectivity works without any BPF. */
	server_fd = start_server(AF_INET, SOCK_STREAM, NULL, port, 0);
	if (!ASSERT_GE(server_fd, 0, "server_fd"))
		return;
	client_fd = connect_to_fd_opts(server_fd, &opts);
	if (!ASSERT_GE(client_fd, 0, "client_fd")) {
		close(server_fd);
		return;
	}
	close(client_fd);
	close(server_fd);

	/* Step 2: Check BPF prog attached to cgroups. */
	cgroup_fd = test__join_cgroup("/cg_skb_get_classid");
	if (!ASSERT_GE(cgroup_fd, 0, "cgroup_fd"))
		return;
	server_fd = start_server(AF_INET, SOCK_STREAM, NULL, port, 0);
	if (!ASSERT_GE(server_fd, 0, "server_fd")) {
		close(cgroup_fd);
		return;
	}
	setup_classid_environment();
	set_classid();
	ASSERT_OK(run_test(cgroup_fd, server_fd), "cg_skb_get_classid");
	cleanup_classid_environment();
	close(server_fd);
	close(cgroup_fd);
}
