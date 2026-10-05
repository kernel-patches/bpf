// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Justin Suess */

#include <sys/stat.h>
#include <sys/xattr.h>
#include <stdlib.h>
#include <unistd.h>
#include <test_progs.h>
#include "path_ancestors.skel.h"

void test_path_ancestors(void)
{
	char base[] = "/tmp/path_ancestors_XXXXXX";
	struct path_ancestors *skel = NULL;
	char suba[280], subb[280];
	bool xattr_works;
	int err;

	if (!ASSERT_OK_PTR(mkdtemp(base), "mkdtemp"))
		return;
	snprintf(suba, sizeof(suba), "%s/a", base);
	snprintf(subb, sizeof(subb), "%s/a/b", base);
	if (!ASSERT_OK(mkdir(suba, 0755), "mkdir_a"))
		goto out_rm;

	/* Read back by the program at the escalated position (== base). */
	err = setxattr(base, "user.walk", "hello", 6, 0);
	xattr_works = !err;
	if (err && errno != EOPNOTSUPP && !ASSERT_OK(err, "setxattr"))
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

	ASSERT_EQ(skel->bss->test_err, 0, "test_err");
	ASSERT_EQ(skel->bss->escalate_err, 0, "escalate_err");
	/* suba, base, /tmp, / at least; equality across modes is the point. */
	ASSERT_GE(skel->bss->rcu_count, 3, "rcu_count");
	ASSERT_EQ(skel->bss->ref_count, skel->bss->rcu_count, "ref_vs_rcu");
	ASSERT_EQ(skel->bss->rcu_ns_count, skel->bss->rcu_count,
		  "nonsleepable_vs_rcu");
	/*
	 * The escalated position is walked twice: once lockless, then again
	 * as the resumed referenced iteration's first position.
	 */
	ASSERT_EQ(skel->bss->hybrid_count, skel->bss->rcu_count + 1,
		  "hybrid_vs_rcu");
	ASSERT_EQ(skel->bss->retry_flags, 0, "no_retry");
	ASSERT_EQ(skel->bss->ref_flags, 0, "ref_flags");

	/* The acquired second position, used after its step was taken. */
	ASSERT_STREQ(skel->bss->second_path, base, "second_path");
	ASSERT_EQ(skel->bss->second_len, strlen(base) + 1, "second_len");

	/* The escalated position is the walk's second one: base. */
	ASSERT_STREQ(skel->bss->escalated_path, base, "escalated_path");
	ASSERT_EQ(skel->bss->escalated_len, strlen(base) + 1, "escalated_len");
	if (xattr_works) {
		ASSERT_EQ(skel->bss->xattr_ret, 6, "xattr_len");
		ASSERT_STREQ(skel->bss->xattr_value, "hello", "xattr_value");
	}

out:
	path_ancestors__destroy(skel);
out_rm:
	rmdir(subb);
	rmdir(suba);
	rmdir(base);
}
