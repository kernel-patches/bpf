// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */
#include <test_progs.h>
#include "timer_mim.skel.h"

static int timer_mim(struct timer_mim *timer_skel)
{
	__u32 duration = 0, retval;
	__u64 cnt1, cnt2;
	int err, prog_fd, key1 = 1;

	err = timer_mim__attach(timer_skel);
	if (!ASSERT_OK(err, "timer_attach"))
		return err;

	prog_fd = bpf_program__fd(timer_skel->progs.test1);
	err = bpf_prog_test_run(prog_fd, 1, NULL, 0,
				NULL, NULL, &retval, &duration);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(retval, 0, "test_run");
	timer_mim__detach(timer_skel);

	/* check that timer_cb[12] are incrementing 'cnt' */
	cnt1 = READ_ONCE(timer_skel->bss->cnt);
	usleep(2);
	cnt2 = READ_ONCE(timer_skel->bss->cnt);
	ASSERT_GT(cnt2, cnt1, "cnt");

	ASSERT_EQ(timer_skel->bss->err, 0, "err");
	/* check that code paths completed */
	ASSERT_EQ(timer_skel->bss->ok, 1 | 2, "ok");

	close(bpf_map__fd(timer_skel->maps.inner_map));
	err = bpf_map_delete_elem(bpf_map__fd(timer_skel->maps.outer_arr), &key1);
	ASSERT_EQ(err, 0, "delete inner map");

	/* check that timer_cb[12] are no longer running */
	cnt1 = READ_ONCE(timer_skel->bss->cnt);
	usleep(2);
	cnt2 = READ_ONCE(timer_skel->bss->cnt);
	ASSERT_EQ(cnt2, cnt1, "cnt");

	return 0;
}

void test_timer_mim(void)
{
	struct timer_mim *timer_skel = NULL;
	int err;

	timer_skel = timer_mim__open_and_load();
	if (!ASSERT_OK_PTR(timer_skel, "timer_skel_load"))
		goto cleanup;

	err = timer_mim(timer_skel);
	ASSERT_OK(err, "timer_mim");
cleanup:
	timer_mim__destroy(timer_skel);
}
