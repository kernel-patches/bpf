// SPDX-License-Identifier: GPL-2.0

#include <sys/types.h>
#include <sys/socket.h>
#include <test_progs.h>

#include "lsm_cgroup_sock.skel.h"

void test_lsm_cgroup_sock(void)
{
	int post_create_prog_fd = -1, bind_prog_fd = -1;
	struct lsm_cgroup_sock *skel = NULL;
	int cgroup_fd, err, fd, prio;
	socklen_t socklen;


	cgroup_fd = test__join_cgroup("/sock_policy");
	if (!ASSERT_GE(cgroup_fd, 0, "join_cgroup"))
		goto close_skel;

	skel = lsm_cgroup_sock__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto close_cgroup;

	err = lsm_cgroup_sock__attach(skel);
	if (!ASSERT_OK(err, "attach"))
		goto close_cgroup;

	post_create_prog_fd = bpf_program__fd(skel->progs.socket_post_create);
	bind_prog_fd = bpf_program__fd(skel->progs.socket_bind);

	err = bpf_prog_attach(post_create_prog_fd, cgroup_fd, BPF_LSM_CGROUP_SOCK, 0);
	if (!ASSERT_OK(err, "attach post_create_prog_fd"))
		goto close_cgroup;

	err = bpf_prog_attach(bind_prog_fd, cgroup_fd, BPF_LSM_CGROUP_SOCK, 0);
	if (!ASSERT_OK(err, "attach bind_prog_fd"))
		goto detach_cgroup;

	/* AF_INET6 gets default policy (sk_priority).
	 */

	fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (!ASSERT_GE(fd, 0, "socket(SOCK_STREAM)"))
		goto detach_cgroup;

	prio = 0;
	socklen = sizeof(prio);
	ASSERT_GE(getsockopt(fd, SOL_SOCKET, SO_PRIORITY, &prio, &socklen), 0, "getsockopt");
	ASSERT_EQ(prio, 123, "sk_priority");

	close(fd);

	/* TX-only AF_PACKET is allowed.
	 */

	ASSERT_LT(socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)), 0, "socket(AF_PACKET, ..., ETH_P_ALL)");

	fd = socket(AF_PACKET, SOCK_RAW, 0);
	ASSERT_GE(fd, 0, "socket(AF_PACKET, ..., 0)");

	/* TX-only AF_PACKET can not be rebound.
	 */

	struct sockaddr_ll sa = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_ALL),
	};
	ASSERT_LT(bind(fd, (struct sockaddr *)&sa, sizeof(sa)), 0, "bind(ETH_P_ALL)");

	close(fd);

detach_cgroup:
	bpf_prog_detach2(post_create_prog_fd, cgroup_fd, BPF_LSM_CGROUP_SOCK);
	bpf_prog_detach2(bind_prog_fd, cgroup_fd, BPF_LSM_CGROUP_SOCK);

close_cgroup:
	close(cgroup_fd);
close_skel:
	lsm_cgroup_sock__destroy(skel);
}
