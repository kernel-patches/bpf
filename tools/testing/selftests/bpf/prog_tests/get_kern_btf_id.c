// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>
#include "get_kern_btf_id.skel.h"

static void test_xdp(void)
{
	struct get_kern_btf_id *skel;
	int err, prog_fd;
	char buf[128];

	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.data_out = buf,
		.data_size_out = sizeof(buf),
		.repeat = 1,
	);

	skel = get_kern_btf_id__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	bpf_program__set_autoload(skel->progs.md_xdp, true);
	err = get_kern_btf_id__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto out;

	prog_fd = bpf_program__fd(skel->progs.md_xdp);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, XDP_PASS, "xdp test_run retval");

	ASSERT_EQ(skel->bss->ifindex, 1, "xdp_md ifindex");
	ASSERT_EQ(skel->bss->ifindex, skel->bss->ingress_ifindex, "xdp_md ingress_ifindex");
	ASSERT_STREQ(skel->bss->name, "lo", "xdp_md name");
	ASSERT_NEQ(skel->bss->inum, 0, "xdp_md inum");

out:
	get_kern_btf_id__destroy(skel);
}

static void test_tc(void)
{
	struct get_kern_btf_id *skel;
	int err, prog_fd;

	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 1,
	);

	skel = get_kern_btf_id__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	bpf_program__set_autoload(skel->progs.md_skb, true);
	err = get_kern_btf_id__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto out;

	prog_fd = bpf_program__fd(skel->progs.md_skb);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, 0, "tc test_run retval");

	ASSERT_EQ(skel->bss->meta_len, 0, "skb meta_len");
	ASSERT_EQ(skel->bss->frag0_len, 0, "skb frag0_len");

out:
	get_kern_btf_id__destroy(skel);
}

void test_get_kern_btf_id(void)
{
	if (test__start_subtest("xdp"))
		test_xdp();
	if (test__start_subtest("tc"))
		test_tc();
}
