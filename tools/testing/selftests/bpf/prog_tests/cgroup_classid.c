// SPDX-License-Identifier: GPL-2.0

#include <sys/types.h>
#include <unistd.h>
#include <test_progs.h>
#include "cgroup_helpers.h"
#include "network_helpers.h"
#include "test_cgroup_classid.skel.h"

#define TEST_CGROUP "/cgroup_classid"

static int test_cgroup_get_classid_from_tc(int cgroup_fd, int srv_fd, int srv_port, bool egress)
{
	struct test_cgroup_classid *skel;
	int cli_fd = -1, ret = -1, expected;

	LIBBPF_OPTS(bpf_tcx_opts, optl);

	skel = test_cgroup_classid__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return ret;

	skel->bss->classid = -1;
	if (egress) {
		expected = getpid();
		skel->links.tc_egress =
			bpf_program__attach_tcx(skel->progs.tc_egress, 1, &optl);
	} else {
		expected = 0;
		skel->links.tc_ingress =
			bpf_program__attach_tcx(skel->progs.tc_ingress, 1, &optl);
	}

	cli_fd = connect_to_fd_opts(srv_fd, NULL);
	if (!ASSERT_GE(cli_fd, 0, "connect_to_fd_opts"))
		goto out;

	ASSERT_EQ(skel->bss->classid, expected, "classid mismatch");
	ret = 0;
out:
	if (cli_fd > 0)
		close(cli_fd);

	test_cgroup_classid__destroy(skel);
	return ret;
}

static void test_cgroup_get_classid_tc(void)
{
	int srv_fd = -1, srv_port = -1;
	int cgroup_fd = -1;

	setup_classid_environment();
	set_classid();
	join_classid();

	cgroup_fd = open_classid();
	if (!ASSERT_GE(cgroup_fd, 0, "open_classid"))
		goto out;

	srv_fd = start_server(AF_INET, SOCK_STREAM, NULL, 0, 0);
	if (!ASSERT_GE(srv_fd, 0, "srv_fd"))
		goto out;

	srv_port = get_socket_local_port(srv_fd);
	if (!ASSERT_GE(srv_port, 0, "get_socket_local_port"))
		goto out;

	ASSERT_OK(test_cgroup_get_classid_from_tc(cgroup_fd, srv_fd, srv_port, 1), "egress");
	ASSERT_OK(test_cgroup_get_classid_from_tc(cgroup_fd, srv_fd, srv_port, 0), "ingress");
out:
	if (srv_fd > 0)
		close(srv_fd);
	if (cgroup_fd > 0)
		close(cgroup_fd);
	cleanup_classid_environment();
}

static void test_cgroup_get_classid_cgroup_dev(void)
{
	struct test_cgroup_classid *skel = NULL;
	int cgroup_fd = -1;

	cgroup_fd = test__join_cgroup(TEST_CGROUP);
	if (!ASSERT_GE(cgroup_fd, 0, "join cgroup"))
		goto out;

	if (!ASSERT_OK(setup_classid_environment(), "setup env"))
		goto out;

	if (!ASSERT_OK(set_classid(), "set_classid"))
		goto out;

	skel = test_cgroup_classid__open_and_load();
	if (!ASSERT_OK_PTR(skel, "load program"))
		goto out;

	skel->links.cg_dev =
		bpf_program__attach_cgroup(skel->progs.cg_dev, cgroup_fd);

	if (!ASSERT_OK_PTR(skel->links.cg_dev, "attach_program"))
		goto out;

	skel->bss->classid = -1;
	if (!ASSERT_OK(join_classid(), "join_classid"))
		goto out;

	open("/dev/null", O_RDWR);
	ASSERT_EQ(skel->bss->classid, getpid(), "classid mismatch");
out:
	if (cgroup_fd > 0)
		close(cgroup_fd);
	test_cgroup_classid__destroy(skel);
	cleanup_classid_environment();
}

static void test_cgroup_get_classid_sysctl(void)
{
	struct test_cgroup_classid *skel = NULL;
	int cgroup_fd = -1;

	cgroup_fd = test__join_cgroup(TEST_CGROUP);
	if (!ASSERT_GE(cgroup_fd, 0, "join cgroup"))
		goto out;

	if (!ASSERT_OK(setup_classid_environment(), "setup env"))
		goto out;

	if (!ASSERT_OK(set_classid(), "set_classid"))
		goto out;

	skel = test_cgroup_classid__open_and_load();
	if (!ASSERT_OK_PTR(skel, "load program"))
		goto out;

	skel->links.sysctl_tcp_mem =
		bpf_program__attach_cgroup(skel->progs.sysctl_tcp_mem, cgroup_fd);
	if (!ASSERT_OK_PTR(skel->links.sysctl_tcp_mem, "attach_program"))
		goto out;

	skel->bss->classid = -1;
	if (!ASSERT_OK(join_classid(), "join_classid"))
		goto out;

	SYS_NOFAIL("cat /proc/sys/net/ipv4/tcp_mem");
	ASSERT_EQ(skel->bss->classid, getpid(), "classid mismatch");
out:
	if (cgroup_fd > 0)
		close(cgroup_fd);
	test_cgroup_classid__destroy(skel);
	cleanup_classid_environment();
}

static void test_cgroup_get_classid_sockopt(void)
{
	struct test_cgroup_classid *skel = NULL;
	int cgroup_fd = -1, fd = -1, val, err;
	socklen_t val_len;

	cgroup_fd = test__join_cgroup(TEST_CGROUP);
	if (!ASSERT_GE(cgroup_fd, 0, "join cgroup"))
		goto out;

	if (!ASSERT_OK(setup_classid_environment(), "setup env"))
		goto out;

	if (!ASSERT_OK(set_classid(), "set_classid"))
		goto out;

	skel = test_cgroup_classid__open_and_load();
	if (!ASSERT_OK_PTR(skel, "load program"))
		goto out;

	skel->links.cg_getsockopt =
		bpf_program__attach_cgroup(skel->progs.cg_getsockopt, cgroup_fd);
	if (!ASSERT_OK_PTR(skel->links.cg_getsockopt, "attach_program"))
		goto out;

	skel->bss->classid = -1;
	if (!ASSERT_OK(join_classid(), "join_classid"))
		goto out;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (!ASSERT_OK_FD(fd, "socket"))
		goto out;

	val_len = sizeof(val);
	err = getsockopt(fd,  SOL_SOCKET, SO_SNDBUF, &val, &val_len);
	if (!ASSERT_OK(err, "getsockopt"))
		goto out;

	ASSERT_EQ(skel->bss->classid, getpid(), "classid mismatch");
out:
	if (fd > 0)
		close(fd);
	if (cgroup_fd > 0)
		close(cgroup_fd);
	test_cgroup_classid__destroy(skel);
	cleanup_classid_environment();
}

void test_cgroup_get_classid(void)
{
	if (test__start_subtest("get classid from tc"))
		test_cgroup_get_classid_tc();
	if (test__start_subtest("get classid from sysctl"))
		test_cgroup_get_classid_sysctl();
	if (test__start_subtest("get classid from cgroup dev"))
		test_cgroup_get_classid_cgroup_dev();
	if (test__start_subtest("get classid from cgroup sockopt"))
		test_cgroup_get_classid_sockopt();
}
