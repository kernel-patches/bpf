// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019 Facebook */

#include <test_progs.h>
#include "test_subskeleton.skel.h"

extern void subskeleton_lib_setup(struct bpf_object *obj);
extern int subskeleton_lib_subresult(struct bpf_object *obj);

void test_subskeleton(void)
{
	int duration = 0, err, result;
	struct test_subskeleton *skel;

	skel = test_subskeleton__open();
	if (CHECK(!skel, "skel_open", "failed to open skeleton\n"))
		return;

	skel->rodata->rovar1 = 10;

	err = test_subskeleton__load(skel);
	if (CHECK(err, "skel_load", "failed to load skeleton: %d\n", err))
		goto cleanup;

	subskeleton_lib_setup(skel->obj);

	err = test_subskeleton__attach(skel);
	if (CHECK(err, "skel_attach", "skeleton attach failed: %d\n", err))
		goto cleanup;

	/* trigger tracepoint */
	usleep(1);

	result = subskeleton_lib_subresult(skel->obj) * 10;
	ASSERT_EQ(skel->bss->out1, result, "unexpected calculation");
cleanup:
	test_subskeleton__destroy(skel);
}
