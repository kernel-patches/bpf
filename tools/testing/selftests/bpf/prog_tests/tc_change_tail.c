// SPDX-License-Identifier: GPL-2.0

#include <error.h>
#include <test_progs.h>
#include <linux/pkt_cls.h>

#include "test_tc_change_tail.skel.h"
#include "socket_helpers.h"

#define LO_IFINDEX 1

void test_tc_change_tail(void)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = LO_IFINDEX,
			.attach_point = BPF_TC_INGRESS);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts);
	struct test_tc_change_tail *skel = NULL;
	bool hook_created = false;
	int ret, fd;
	int c1, p1;
	char buf[2];

	skel = test_tc_change_tail__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_tc_change_tail__open_and_load"))
		return;
	ret = bpf_tc_hook_create(&hook);
	if (ret == 0)
		hook_created = true;
	ret = ret == -EEXIST ? 0 : ret;
	if (!ASSERT_OK(ret, "bpf_tc_hook_create"))
		goto destroy;
	fd = bpf_program__fd(skel->progs.change_tail);
	opts.prog_fd = fd;
	opts.handle = 1;
	opts.priority = 1;
	opts.flags = BPF_TC_F_REPLACE;
	ret = bpf_tc_attach(&hook, &opts);
	if (!ASSERT_OK(ret, "bpf_tc_attach"))
		goto hook_destroy;

	ret = create_pair(AF_INET, SOCK_STREAM, &c1, &p1);
	if (!ASSERT_OK(ret, "create_pair"))
		goto detach;

	ret = xsend(p1, "Tr", 2, 0);
	ASSERT_EQ(ret, 2, "xsend(p1)");
	ret = recv(c1, buf, 2, 0);
	ASSERT_EQ(ret, 2, "recv(c1)");
	ASSERT_EQ(skel->data->change_tail_ret, 0, "change_tail_ret");

	ret = xsend(p1, "G", 1, 0);
	ASSERT_EQ(ret, 1, "xsend(p1)");
	ret = recv(c1, buf, 1, 0);
	ASSERT_EQ(ret, 1, "recv(c1)");
	ASSERT_EQ(skel->data->change_tail_ret, 0, "change_tail_ret");

	ret = xsend(p1, "E", 1, 0);
	ASSERT_EQ(ret, 1, "xsend(p1)");
	ret = recv(c1, buf, 1, 0);
	ASSERT_EQ(ret, 1, "recv(c1)");
	ASSERT_EQ(skel->data->change_tail_ret, -EINVAL, "change_tail_ret");

	ret = xsend(p1, "Z", 1, 0);
	ASSERT_EQ(ret, 1, "xsend(p1)");
	ret = recv(c1, buf, 1, 0);
	ASSERT_EQ(ret, 1, "recv(c1)");
	ASSERT_EQ(skel->data->change_tail_ret, -EINVAL, "change_tail_ret");

	close(c1);
	close(p1);
detach:
	bpf_tc_detach(&hook, &opts);
hook_destroy:
	if (hook_created)
		bpf_tc_hook_destroy(&hook);
destroy:
	test_tc_change_tail__destroy(skel);
}
