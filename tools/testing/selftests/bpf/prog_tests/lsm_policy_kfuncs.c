// SPDX-License-Identifier: GPL-2.0
/* Copyright © 2026 Justin Suess <utilityemal77@gmail.com> */

#include <test_progs.h>
#include <stdlib.h>
#include <unistd.h>

#include "lsm_policy_kfuncs.skel.h"
#include "lsm_policy_kfuncs_failure.skel.h"

/*
 * Runtime contract of bpf_lsm_policy_from_fd(), independent of any
 * LSM implementing the policy object hooks: a bad fd, a fd that is no
 * LSM's policy object, and a nonzero value of the reserved flags all
 * resolve to NULL.
 */
static void test_from_fd_null(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct lsm_policy_kfuncs *skel;
	char tmp_path[] = "/tmp/lsm_policy_kfuncs_XXXXXX";
	int tmp_fd, err;

	tmp_fd = mkstemp(tmp_path);
	if (!ASSERT_GE(tmp_fd, 0, "mkstemp"))
		return;

	skel = lsm_policy_kfuncs__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		goto out_close;
	skel->bss->plain_fd = tmp_fd;

	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.check_from_fd),
				     &opts);
	if (!ASSERT_OK(err, "check_from_fd_run") ||
	    !ASSERT_OK(opts.retval, "check_from_fd_retval"))
		goto out_destroy;

	ASSERT_TRUE(skel->bss->got_null_for_bad_fd, "bad_fd_null");
	ASSERT_TRUE(skel->bss->got_null_for_plain_fd, "plain_fd_null");
	ASSERT_TRUE(skel->bss->got_null_for_bad_flags, "bad_flags_null");
out_destroy:
	lsm_policy_kfuncs__destroy(skel);
out_close:
	close(tmp_fd);
	unlink(tmp_path);
}

void test_lsm_policy_kfuncs(void)
{
	if (test__start_subtest("from_fd_null"))
		test_from_fd_null();
	RUN_TESTS(lsm_policy_kfuncs_failure);
}
