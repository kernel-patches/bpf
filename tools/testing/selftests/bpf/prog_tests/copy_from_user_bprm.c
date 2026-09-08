// SPDX-License-Identifier: GPL-2.0

#include <errno.h>
#include <sys/wait.h>
#include <unistd.h>

#include <test_progs.h>

#include "copy_from_user_bprm.skel.h"

void test_copy_from_user_bprm(void)
{
	char arg0[] = "first";
	char arg1[] = "second-argument";
	char env0[] = "SOME_ENV=a";
	char env1[] = "OTHER_ENV=something";
	struct copy_from_user_bprm *skel;
	pid_t child;
	int status;

	skel = copy_from_user_bprm__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	/*
	 * On !CONFIG_MMU, exec strings are held in bprm->page[] rather than
	 * being mapped in bprm->mm.
	 */
	if (!skel->kconfig->CONFIG_MMU) {
		printf("%s:SKIP: test requires CONFIG_MMU\n", __func__);
		test__skip();
		goto out;
	}

	if (!ASSERT_OK(copy_from_user_bprm__attach(skel), "attach"))
		goto out;

	child = fork();
	if (!ASSERT_GE(child, 0, "fork"))
		goto out;

	if (!child) {
		char *const argv[] = { arg0, arg1, NULL };
		char *const envp[] = { env0, env1, NULL };

		skel->bss->monitored_pid = getpid();
		execve("/bin/true", argv, envp);
		_exit(errno);
	}

	if (!ASSERT_EQ(waitpid(child, &status, 0), child, "waitpid"))
		goto out;

	if (ASSERT_TRUE(WIFEXITED(status), "child_exited"))
		ASSERT_EQ(WEXITSTATUS(status), EPERM, "exec_errno");

	ASSERT_EQ(skel->bss->bprm_argc, 2, "bprm_argc");
	ASSERT_EQ(skel->bss->bprm_envc, 2, "bprm_envc");
	ASSERT_EQ(skel->bss->data_len_match, 1, "data_len_match");
	ASSERT_EQ(skel->bss->invalid_flags_ret, -EINVAL, "invalid_flags_ret");
	ASSERT_EQ(skel->bss->copy_ret, 0, "copy_ret");
	ASSERT_EQ(skel->bss->str_arg0_ret, sizeof(arg0), "str_arg0_ret");
	ASSERT_EQ(skel->bss->str_arg1_ret, sizeof(arg1), "str_arg1_ret");
	ASSERT_EQ(skel->bss->str_env0_ret, sizeof(env0), "str_env0_ret");
	ASSERT_EQ(skel->bss->str_env1_ret, sizeof(env1), "str_env1_ret");
	ASSERT_EQ(skel->bss->data_match, 1, "data_match");
	ASSERT_EQ(skel->bss->str_args_match, 1, "str_args_match");
	ASSERT_EQ(skel->bss->str_envs_match, 1, "str_envs_match");

out:
	copy_from_user_bprm__destroy(skel);
}
