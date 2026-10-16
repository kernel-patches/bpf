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
	int attempt;

	if (!ASSERT_OK_PTR(mkdtemp(base), "mkdtemp"))
		return;
	snprintf(suba, sizeof(suba), "%s/a", base);
	if (!ASSERT_OK(mkdir(suba, 0755), "mkdir_a"))
		goto out_rm;

	skel = path_ancestors__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto out_rm;
	if (!ASSERT_OK(path_ancestors__attach(skel), "attach"))
		goto out;

	/*
	 * A mount anywhere in the system during the walk legitimately ends
	 * the lockless iterations with RETRY and no conclusion: retrigger
	 * until a quiet window.  mkdir b: the hook sees dir == suba, whose
	 * ancestry is walked.
	 */
	for (attempt = 0; attempt < 5; attempt++) {
		memset(skel->bss, 0, sizeof(*skel->bss));
		skel->bss->monitored_pid = getpid();

		snprintf(subb, sizeof(subb), "%s/a/b%d", base, attempt);
		if (!ASSERT_OK(mkdir(subb, 0755), "mkdir_b"))
			goto out;
		rmdir(subb);
		if (!skel->bss->retry_flags && !skel->bss->escalate_err)
			break;
	}
	if (!ASSERT_LT(attempt, 5, "retried_out"))
		goto out;

	ASSERT_EQ(skel->bss->escalate_err, 0, "escalate_err");
	/* suba, base, /tmp, / at least; equality across modes is the point. */
	ASSERT_GE(skel->bss->rcu_count, 4, "rcu_count");
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
	/*
	 * The referenced loops ended at the root, not on an allocation
	 * failure.
	 */
	ASSERT_EQ(skel->bss->end_flags, 0, "end_flags");

	/* The acquired second position, used after its step was taken. */
	ASSERT_STREQ(skel->bss->second_path, base, "second_path");
	ASSERT_EQ(skel->bss->second_len, strlen(base) + 1, "second_len");

	/* The first position, used only after the walk itself was gone. */
	ASSERT_STREQ(skel->bss->first_path, suba, "first_path");
	ASSERT_EQ(skel->bss->first_len, strlen(suba) + 1, "first_len");

	/* The escalated position is the walk's second one: base. */
	ASSERT_STREQ(skel->bss->escalated_path, base, "escalated_path");
	ASSERT_EQ(skel->bss->escalated_len, strlen(base) + 1, "escalated_len");

out:
	path_ancestors__destroy(skel);
out_rm:
	rmdir(suba);
	rmdir(base);
}
