// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022, Oracle and/or its affiliates. */

#include <test_progs.h>
#include "test_uprobe_autoattach.skel.h"

/* uprobe attach point */
static noinline int autoattach_trigger_func(int arg)
{
	return arg + 1;
}

void test_uprobe_autoattach(void)
{
	struct test_uprobe_autoattach *skel;
	int trigger_val = 100;
	size_t malloc_sz = 1;
	char *mem;

	skel = test_uprobe_autoattach__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	if (!ASSERT_OK(test_uprobe_autoattach__attach(skel), "skel_attach"))
		goto cleanup;

	skel->bss->uprobe_byname_parm1 = trigger_val;
	skel->bss->uretprobe_byname_rc  = trigger_val + 1;
	skel->bss->uprobe_byname2_parm1 = malloc_sz;
	skel->bss->uretprobe_byname2_rc = getpid();

	/* trigger & validate uprobe & uretprobe */
	(void) autoattach_trigger_func(trigger_val);

	/* trigger & validate shared library u[ret]probes attached by name */
	mem = malloc(malloc_sz);
	free(mem);
	(void) getpid();

	ASSERT_EQ(skel->bss->uprobe_byname_res, 1, "check_uprobe_byname_res");
	ASSERT_EQ(skel->bss->uretprobe_byname_res, 2, "check_uretprobe_byname_res");
	ASSERT_EQ(skel->bss->uprobe_byname2_res, 3, "check_uprobe_byname2_res");
	ASSERT_EQ(skel->bss->uretprobe_byname2_res, 4, "check_uretprobe_byname2_res");
cleanup:
	test_uprobe_autoattach__destroy(skel);
}
