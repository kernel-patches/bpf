// SPDX-License-Identifier: GPL-2.0

#include <unistd.h>
#include <linux/kernel.h>
#include <test_progs.h>
#include <network_helpers.h>

#include "test_xdp_multi_buff.skel.h"

static void test_xdp_mb_check_len(void)
{
	int test_sizes[] = { 128, 4096, 9000 };
	struct test_xdp_multi_buff *pkt_skel;
	__u8 *pkt_in = NULL, *pkt_out = NULL;
	__u32 duration = 0, retval, size;
	int err, pkt_fd, i;

	/* Load XDP program */
	pkt_skel = test_xdp_multi_buff__open_and_load();
	if (CHECK(!pkt_skel, "pkt_skel_load", "test_xdp_mb skeleton failed\n"))
		goto out;

	/* Allocate resources */
	pkt_out = malloc(test_sizes[ARRAY_SIZE(test_sizes) - 1]);
	if (CHECK(!pkt_out, "malloc", "Failed pkt_out malloc\n"))
		goto out;

	pkt_in = malloc(test_sizes[ARRAY_SIZE(test_sizes) - 1]);
	if (CHECK(!pkt_in, "malloc", "Failed pkt_in malloc\n"))
		goto out;

	pkt_fd = bpf_program__fd(pkt_skel->progs._xdp_check_mb_len);
	if (pkt_fd < 0)
		goto out;

	/* Run test for specific set of packets */
	for (i = 0; i < ARRAY_SIZE(test_sizes); i++) {
		int frags_count;

		/* Run test program */
		err = bpf_prog_test_run(pkt_fd, 1, pkt_in, test_sizes[i],
					pkt_out, &size, &retval, &duration);

		if (CHECK(err || retval != XDP_PASS || size != test_sizes[i],
			  "test_run", "err %d errno %d retval %d size %d[%d]\n",
			  err, errno, retval, size, test_sizes[i]))
			goto out;

		/* Verify test results */
		frags_count = DIV_ROUND_UP(
			test_sizes[i] - pkt_skel->data->test_result_xdp_len,
			getpagesize());

		if (CHECK(pkt_skel->data->test_result_frags_count != frags_count,
			  "result", "frags_count = %llu != %u\n",
			  pkt_skel->data->test_result_frags_count, frags_count))
			goto out;

		if (CHECK(pkt_skel->data->test_result_frags_len != test_sizes[i] -
			  pkt_skel->data->test_result_xdp_len,
			  "result", "frags_len = %llu != %llu\n",
			  pkt_skel->data->test_result_frags_len,
			  test_sizes[i] - pkt_skel->data->test_result_xdp_len))
			goto out;
	}
out:
	if (pkt_out)
		free(pkt_out);
	if (pkt_in)
		free(pkt_in);

	test_xdp_multi_buff__destroy(pkt_skel);
}

void test_xdp_mb(void)
{
	if (test__start_subtest("xdp_mb_check_len_frags"))
		test_xdp_mb_check_len();
}
