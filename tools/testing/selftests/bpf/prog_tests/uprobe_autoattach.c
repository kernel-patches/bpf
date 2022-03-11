// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022, Oracle and/or its affiliates. */

#include <test_progs.h>
#include "test_uprobe_autoattach.skel.h"

/* uprobe attach point */
static void autoattach_trigger_func(void)
{
	asm volatile ("");
}

void test_uprobe_autoattach(void)
{
	struct test_uprobe_autoattach *skel;
	char *mem;

	skel = test_uprobe_autoattach__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;
	if (!ASSERT_OK_PTR(skel->bss, "check_bss"))
		goto cleanup;

	if (!ASSERT_OK(test_uprobe_autoattach__attach(skel), "skel_attach"))
		goto cleanup;

	/* trigger & validate uprobe & uretprobe */
	autoattach_trigger_func();

	/* trigger & validate shared library u[ret]probes attached by name */
	mem = malloc(1);
	free(mem);

	if (!ASSERT_EQ(skel->bss->uprobe_byname_res, 1, "check_uprobe_byname_res"))
		goto cleanup;
	if (!ASSERT_EQ(skel->bss->uretprobe_byname_res, 2, "check_uretprobe_byname_res"))
		goto cleanup;
	if (!ASSERT_EQ(skel->bss->uprobe_byname2_res, 3, "check_uprobe_byname2_res"))
		goto cleanup;
	if (!ASSERT_EQ(skel->bss->uretprobe_byname2_res, 4, "check_uretprobe_byname2_res"))
		goto cleanup;
	if (!ASSERT_EQ(skel->bss->uprobe_byname3_res, 5, "check_uprobe_byname3_res"))
		goto cleanup;
	if (!ASSERT_EQ(skel->bss->uretprobe_byname3_res, 6, "check_uretprobe_byname3_res"))
		goto cleanup;
cleanup:
	test_uprobe_autoattach__destroy(skel);
}
