// SPDX-License-Identifier: GPL-2.0

#include <sys/types.h>
#include <sys/socket.h>
#include <test_progs.h>

#include "lsm_cgroup.skel.h"
#include "cgroup_helpers.h"

void test_lsm_cgroup(void)
{
	DECLARE_LIBBPF_OPTS(bpf_prog_attach_opts, attach_opts);
	DECLARE_LIBBPF_OPTS(bpf_link_update_opts, update_opts);
	int cgroup_fd, cgroup_fd2, err, fd, prio;
	struct lsm_cgroup *skel = NULL;
	int post_create_prog_fd2 = -1;
	int post_create_prog_fd = -1;
	int bind_link_fd2 = -1;
	int bind_prog_fd2 = -1;
	int alloc_prog_fd = -1;
	int bind_prog_fd = -1;
	int bind_link_fd = -1;
	socklen_t socklen;

	cgroup_fd = test__join_cgroup("/sock_policy");
	if (!ASSERT_GE(cgroup_fd, 0, "join_cgroup"))
		goto close_skel;

	cgroup_fd2 = create_and_get_cgroup("/sock_policy2");
	if (!ASSERT_GE(cgroup_fd2, 0, "create second cgroup"))
		goto close_skel;

	skel = lsm_cgroup__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto close_cgroup;

	post_create_prog_fd = bpf_program__fd(skel->progs.socket_post_create);
	post_create_prog_fd2 = bpf_program__fd(skel->progs.socket_post_create2);
	bind_prog_fd = bpf_program__fd(skel->progs.socket_bind);
	bind_prog_fd2 = bpf_program__fd(skel->progs.socket_bind2);
	alloc_prog_fd = bpf_program__fd(skel->progs.socket_alloc);

	err = bpf_prog_attach(alloc_prog_fd, cgroup_fd, BPF_LSM_CGROUP, 0);
	if (!ASSERT_OK(err, "attach alloc_prog_fd"))
		goto detach_cgroup;

	/* Make sure replacing works.
	 */

	err = bpf_prog_attach(post_create_prog_fd, cgroup_fd,
			      BPF_LSM_CGROUP, 0);
	if (!ASSERT_OK(err, "attach post_create_prog_fd"))
		goto close_cgroup;

	attach_opts.replace_prog_fd = post_create_prog_fd;
	err = bpf_prog_attach_opts(post_create_prog_fd2, cgroup_fd,
				   BPF_LSM_CGROUP, &attach_opts);
	if (!ASSERT_OK(err, "prog replace post_create_prog_fd"))
		goto detach_cgroup;

	/* Try the same attach/replace via link API.
	 */

	bind_link_fd = bpf_link_create(bind_prog_fd, cgroup_fd,
				       BPF_LSM_CGROUP, NULL);
	if (!ASSERT_GE(bind_link_fd, 0, "link create bind_prog_fd"))
		goto detach_cgroup;

	update_opts.old_prog_fd = bind_prog_fd;
	update_opts.flags = BPF_F_REPLACE;

	err = bpf_link_update(bind_link_fd, bind_prog_fd2, &update_opts);
	if (!ASSERT_OK(err, "link update bind_prog_fd"))
		goto detach_cgroup;

	/* Attach another instance of bind program to another cgroup.
	 * This should trigger the reuse of the trampoline shim (two
	 * programs attaching to the same btf_id).
	 */

	bind_link_fd2 = bpf_link_create(bind_prog_fd2, cgroup_fd2,
					BPF_LSM_CGROUP, NULL);
	if (!ASSERT_GE(bind_link_fd2, 0, "link create bind_prog_fd2"))
		goto detach_cgroup;

	/* AF_UNIX is prohibited.
	 */

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	ASSERT_LT(fd, 0, "socket(AF_UNIX)");

	/* AF_INET6 gets default policy (sk_priority).
	 */

	fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (!ASSERT_GE(fd, 0, "socket(SOCK_STREAM)"))
		goto detach_cgroup;

	prio = 0;
	socklen = sizeof(prio);
	ASSERT_GE(getsockopt(fd, SOL_SOCKET, SO_PRIORITY, &prio, &socklen), 0,
		  "getsockopt");
	ASSERT_EQ(prio, 123, "sk_priority");

	close(fd);

	/* TX-only AF_PACKET is allowed.
	 */

	ASSERT_LT(socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)), 0,
		  "socket(AF_PACKET, ..., ETH_P_ALL)");

	fd = socket(AF_PACKET, SOCK_RAW, 0);
	ASSERT_GE(fd, 0, "socket(AF_PACKET, ..., 0)");

	/* TX-only AF_PACKET can not be rebound.
	 */

	struct sockaddr_ll sa = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_ALL),
	};
	ASSERT_LT(bind(fd, (struct sockaddr *)&sa, sizeof(sa)), 0,
		  "bind(ETH_P_ALL)");

	close(fd);

	/* Make sure other cgroup doesn't trigger the programs.
	 */

	if (!ASSERT_OK(join_cgroup(""), "join root cgroup"))
		goto detach_cgroup;

	fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (!ASSERT_GE(fd, 0, "socket(SOCK_STREAM)"))
		goto detach_cgroup;

	prio = 0;
	socklen = sizeof(prio);
	ASSERT_GE(getsockopt(fd, SOL_SOCKET, SO_PRIORITY, &prio, &socklen), 0,
		  "getsockopt");
	ASSERT_EQ(prio, 0, "sk_priority");

	close(fd);

detach_cgroup:
	ASSERT_GE(bpf_prog_detach2(post_create_prog_fd2, cgroup_fd,
				   BPF_LSM_CGROUP), 0, "detach_create");
	close(bind_link_fd);
	/* Don't close bind_link_fd2, exercise cgroup release cleanup. */
	ASSERT_GE(bpf_prog_detach2(alloc_prog_fd, cgroup_fd,
				   BPF_LSM_CGROUP), 0, "detach_alloc");

close_cgroup:
	close(cgroup_fd);
close_skel:
	lsm_cgroup__destroy(skel);
}
