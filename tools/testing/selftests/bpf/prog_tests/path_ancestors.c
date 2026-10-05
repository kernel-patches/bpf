// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Justin Suess */

#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <test_progs.h>
#include "path_ancestors.skel.h"

void test_path_ancestors(void)
{
	char base[] = "/tmp/path_ancestors_XXXXXX";
	struct path_ancestors *skel = NULL;
	char suba[280], subb[280];

	if (!ASSERT_OK_PTR(mkdtemp(base), "mkdtemp"))
		return;
	snprintf(suba, sizeof(suba), "%s/a", base);
	snprintf(subb, sizeof(subb), "%s/a/b", base);
	if (!ASSERT_OK(mkdir(suba, 0755), "mkdir_a"))
		goto out_rm;

	skel = path_ancestors__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto out_rm;
	skel->bss->monitored_pid = getpid();
	if (!ASSERT_OK(path_ancestors__attach(skel), "attach"))
		goto out;

	/* mkdir b: the hook sees dir == suba, whose ancestry is walked. */
	if (!ASSERT_OK(mkdir(subb, 0755), "mkdir_b"))
		goto out;

	/* suba, base, /tmp, / at least. */
	ASSERT_GE(skel->bss->ref_count, 3, "ref_count");
	ASSERT_EQ(skel->bss->ref_flags, 0, "ref_flags");

	/* The acquired second position, used after its step was taken. */
	ASSERT_STREQ(skel->bss->second_path, base, "second_path");
	ASSERT_EQ(skel->bss->second_len, strlen(base) + 1, "second_len");

out:
	path_ancestors__destroy(skel);
out_rm:
	rmdir(subb);
	rmdir(suba);
	rmdir(base);
}
