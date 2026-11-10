// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>
#include "test_xdp_skb_ext.skel.h"
#include "xdp_skb_ext_success.skel.h"
#include "xdp_skb_ext_failure.skel.h"

/* The area of a reused page is not valid for the next packet */
static void test_live_frames(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		    .data_in = &pkt_v4,
		    .data_size_in = sizeof(pkt_v4),
		    .flags = BPF_F_TEST_XDP_LIVE_FRAMES,
		    .repeat = 256,
	);
	struct test_xdp_skb_ext *skel;
	int prog_fd;

	skel = test_xdp_skb_ext__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_xdp_skb_ext__open_and_load"))
		return;

	prog_fd = bpf_program__fd(skel->progs.live_frames);
	if (!ASSERT_OK(bpf_prog_test_run_opts(prog_fd, &opts), "test_run"))
		goto out;
	ASSERT_GT(skel->bss->reused_ok, 0, "reused_ok");
	ASSERT_EQ(skel->bss->reused_bad, 0, "reused_bad");
	ASSERT_EQ(skel->bss->store_err, 0, "store_err");
out:
	test_xdp_skb_ext__destroy(skel);
}

void test_xdp_skb_ext(void)
{
	RUN_TESTS(xdp_skb_ext_success);
	RUN_TESTS(xdp_skb_ext_failure);

	if (test__start_subtest("live_frames"))
		test_live_frames();
}
