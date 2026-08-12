// SPDX-License-Identifier: GPL-2.0

#include <errno.h>
#include <sys/wait.h>
#include <unistd.h>

#include <test_progs.h>

#include "copy_from_user_bprm.skel.h"

void test_copy_from_user_bprm(void)
{
	struct copy_from_user_bprm *skel;
	pid_t child;
	int status;

	skel = copy_from_user_bprm__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	if (!ASSERT_OK(copy_from_user_bprm__attach(skel), "attach"))
		goto out;

	child = fork();
	if (!ASSERT_GE(child, 0, "fork"))
		goto out;

	if (!child) {
		char *const argv[] = { "first", "second-argument", NULL };

		skel->bss->monitored_pid = getpid();
		execv("/bin/true", argv);
		_exit(errno);
	}

	if (!ASSERT_EQ(waitpid(child, &status, 0), child, "waitpid"))
		goto out;

	if (ASSERT_TRUE(WIFEXITED(status), "child_exited"))
		ASSERT_EQ(WEXITSTATUS(status), EPERM, "exec_errno");

	ASSERT_EQ(skel->bss->bprm_argc, 2, "bprm_argc");
	ASSERT_EQ(skel->bss->invalid_flags_ret, -EINVAL, "invalid_flags_ret");
	ASSERT_EQ(skel->bss->copy_ret, 0, "copy_ret");
	ASSERT_EQ(skel->bss->str_arg0_ret, 6, "str_arg0_ret");
	ASSERT_EQ(skel->bss->str_arg1_ret, 16, "str_arg1_ret");
	ASSERT_EQ(skel->bss->args_match, 1, "args_match");
	ASSERT_EQ(skel->bss->str_args_match, 1, "str_args_match");

out:
	copy_from_user_bprm__destroy(skel);
}
