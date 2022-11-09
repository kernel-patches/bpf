// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>
#include "test_xdp_md.skel.h"

void test_xdp_md(void)
{
	struct test_xdp_md *skel;
	int err, prog_fd;
	char buf[128];

	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.data_out = buf,
		.data_size_out = sizeof(buf),
		.repeat = 1,
	);

	skel = test_xdp_md__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	prog_fd = bpf_program__fd(skel->progs.md_xdp);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, XDP_PASS, "xdp_md test_run retval");

	ASSERT_EQ(skel->bss->ifindex, 1, "xdp_md ifindex");
	ASSERT_EQ(skel->bss->ifindex, skel->bss->ingress_ifindex, "xdp_md ingress_ifindex");
	ASSERT_STREQ(skel->bss->name, "lo", "xdp_md name");
	ASSERT_NEQ(skel->bss->inum, 0, "xdp_md inum");

	test_xdp_md__destroy(skel);
}
