// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */

#include <test_progs.h>
#include <network_helpers.h>
#include "bpf_loop.skel.h"

static void check_nr_loops(struct bpf_loop *skel)
{
	__u32 retval, duration;
	int err;

	/* test 0 loops */
	skel->bss->nr_loops = 0;
	err = bpf_prog_test_run(bpf_program__fd(skel->progs.test_prog),
				1, &pkt_v4, sizeof(pkt_v4), NULL, NULL,
				&retval, &duration);
	if (!ASSERT_OK(err, "err") || !ASSERT_OK(retval, "retval"))
		return;
	ASSERT_EQ(skel->bss->nr_loops_returned, skel->bss->nr_loops,
		  "0 loops");

	/* test 500 loops */
	skel->bss->nr_loops = 500;
	err = bpf_prog_test_run(bpf_program__fd(skel->progs.test_prog),
				1, &pkt_v4, sizeof(pkt_v4), NULL, NULL,
				&retval, &duration);
	if (!ASSERT_OK(err, "err") ||
	    !ASSERT_OK(retval, "retval"))
		return;
	ASSERT_EQ(skel->bss->nr_loops_returned, skel->bss->nr_loops,
		  "500 loops");
	ASSERT_EQ(skel->bss->g_output, (500 * 499) / 2, "g_output");

	/* test exceeding the max limit */
	skel->bss->nr_loops = -1;
	err = bpf_prog_test_run(bpf_program__fd(skel->progs.test_prog),
				1, &pkt_v4, sizeof(pkt_v4), NULL, NULL,
				&retval, &duration);
	if (!ASSERT_OK(err, "err") || !ASSERT_OK(retval, "retval"))
		return;
	ASSERT_EQ(skel->bss->err, -EINVAL, "over max limit");
}

static void check_callback_fn_stop(struct bpf_loop *skel)
{
	__u32 retval, duration;
	int err;

	skel->bss->nr_loops = 400;
	skel->data->stop_index = 50;

	/* testing that loop is stopped when callback_fn returns 1 */
	err = bpf_prog_test_run(bpf_program__fd(skel->progs.test_prog),
				1, &pkt_v4, sizeof(pkt_v4), NULL, NULL,
				&retval, &duration);

	if (!ASSERT_OK(err, "err") || !ASSERT_OK(retval, "retval"))
		return;

	ASSERT_EQ(skel->bss->nr_loops_returned, skel->data->stop_index + 1,
		  "nr_loops_returned");
	ASSERT_EQ(skel->bss->g_output, (50 * 49) / 2,
		  "g_output");
}

static void check_null_callback_ctx(struct bpf_loop *skel)
{
	__u32 retval, duration;
	int err;

	skel->bss->nr_loops = 10;

	/* check that user is able to pass in a null callback_ctx */
	err = bpf_prog_test_run(bpf_program__fd(skel->progs.prog_null_ctx),
				1, &pkt_v4, sizeof(pkt_v4), NULL, NULL,
				&retval, &duration);

	if (!ASSERT_OK(err, "err") || !ASSERT_OK(retval, "retval"))
		return;

	ASSERT_EQ(skel->bss->nr_loops_returned, skel->bss->nr_loops,
		  "nr_loops_returned");
}

static void check_invalid_flags(struct bpf_loop *skel)
{
	__u32 retval, duration;
	int err;

	/* check that passing in non-zero flags returns -EINVAL */
	err = bpf_prog_test_run(bpf_program__fd(skel->progs.prog_invalid_flags),
				1, &pkt_v4, sizeof(pkt_v4), NULL, NULL,
				&retval, &duration);

	if (!ASSERT_OK(err, "err") || !ASSERT_OK(retval, "retval"))
		return;

	ASSERT_EQ(skel->bss->err, -EINVAL, "err");
}

static void check_nested_calls(struct bpf_loop *skel)
{
	__u32 nr_loops = 100, nested_callback_nr_loops = 4;
	__u32 retval, duration;
	int err;

	skel->bss->nr_loops = nr_loops;
	skel->bss->nested_callback_nr_loops = nested_callback_nr_loops;

	/* check that nested calls are supported */
	err = bpf_prog_test_run(bpf_program__fd(skel->progs.prog_nested_calls),
				1, &pkt_v4, sizeof(pkt_v4), NULL, NULL,
				&retval, &duration);
	if (!ASSERT_OK(err, "err") || !ASSERT_OK(retval, "retval"))
		return;
	ASSERT_EQ(skel->bss->nr_loops_returned, nr_loops * nested_callback_nr_loops
		  * nested_callback_nr_loops, "nr_loops_returned");
	ASSERT_EQ(skel->bss->g_output, (4 * 3) / 2 * nested_callback_nr_loops
		* nr_loops, "g_output");
}

void test_bpf_loop(void)
{
	struct bpf_loop *skel;

	skel = bpf_loop__open_and_load();
	if (!ASSERT_OK_PTR(skel, "bpf_loop__open_and_load"))
		return;

	check_nr_loops(skel);
	check_callback_fn_stop(skel);
	check_null_callback_ctx(skel);
	check_invalid_flags(skel);
	check_nested_calls(skel);

	bpf_loop__destroy(skel);
}
