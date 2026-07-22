// SPDX-License-Identifier: GPL-2.0

#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <test_progs.h>

#include "copy_from_user_bprm.skel.h"

void test_copy_from_user_bprm(void)
{
	struct copy_from_user_bprm *skel;
	int sync_pipe[2];
	int status;
	pid_t child;
	char token;

	skel = copy_from_user_bprm__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	if (!ASSERT_OK(copy_from_user_bprm__attach(skel), "attach"))
		goto out;
	if (!ASSERT_OK(pipe(sync_pipe), "pipe"))
		goto out;

	child = fork();
	if (!ASSERT_GE(child, 0, "fork")) {
		close(sync_pipe[0]);
		close(sync_pipe[1]);
		goto out;
	}

	if (!child) {
		char *const argv[] = { "bpf-copy-bprm", "deny", NULL };

		close(sync_pipe[1]);
		if (read(sync_pipe[0], &token, 1) != 1)
			_exit(EIO);
		close(sync_pipe[0]);

		execv("/bin/true", argv);
		_exit(errno);
	}

	close(sync_pipe[0]);
	skel->bss->monitored_pid = child;
	if (!ASSERT_EQ(write(sync_pipe[1], "x", 1), 1, "sync_child")) {
		close(sync_pipe[1]);
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		goto out;
	}
	close(sync_pipe[1]);

	if (!ASSERT_EQ(waitpid(child, &status, 0), child, "waitpid"))
		goto out;
	if (ASSERT_TRUE(WIFEXITED(status), "child_exited"))
		ASSERT_EQ(WEXITSTATUS(status), EPERM, "exec_errno");
	ASSERT_EQ(skel->bss->invalid_flags_ret, -EINVAL, "invalid_flags_ret");
	ASSERT_EQ(skel->bss->copy_ret, 0, "copy_ret");
	ASSERT_EQ(skel->bss->str_arg0_ret, 14, "str_arg0_ret");
	ASSERT_EQ(skel->bss->str_arg1_ret, 5, "str_arg1_ret");
	ASSERT_EQ(skel->bss->hook_calls, 1, "hook_calls");
	ASSERT_TRUE(skel->bss->args_match, "args_match");
	ASSERT_TRUE(skel->bss->str_args_match, "str_args_match");

out:
	copy_from_user_bprm__destroy(skel);
}
