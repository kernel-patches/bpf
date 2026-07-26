// SPDX-License-Identifier: GPL-2.0
/* Copyright © 2026 Justin Suess <utilityemal77@gmail.com> */

#include <test_progs.h>
#include <errno.h>
#include <linux/landlock.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "lsm_policy_kfuncs_success.skel.h"
#include "lsm_policy_kfuncs_failure.skel.h"

/* Fallbacks for old system headers. */
#ifndef LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON
#define LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON (1U << 1)
#endif
#ifndef LANDLOCK_RESTRICT_SELF_TSYNC
#define LANDLOCK_RESTRICT_SELF_TSYNC (1U << 3)
#endif

static int create_ruleset(void)
{
	const struct landlock_ruleset_attr attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_WRITE_FILE,
	};

	return syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr), 0);
}

static void reset_prog_state(struct lsm_policy_kfuncs_success *skel)
{
	skel->bss->called = false;
	skel->bss->no_ruleset = false;
	skel->bss->restrict_err = -1;
	skel->bss->restrict2_err = -1;
	skel->bss->kfunc_flags = 0;
	skel->bss->double_call = false;
}

/* Runs the syscall program that acquires the ruleset from
 * @ruleset_fd, in the runner's fd table, and parks it in the map kptr
 * slot for the LSM program.
 */
static int load_ruleset_into_map(struct lsm_policy_kfuncs_success *skel)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err;

	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.load_ruleset),
				     &opts);
	if (!ASSERT_OK(err, "load_ruleset_run"))
		return -1;
	if (!ASSERT_OK(opts.retval, "load_ruleset_retval"))
		return -1;
	ASSERT_TRUE(skel->bss->got_null_for_bad_fd, "bad_fd_null");
	return 0;
}

/* Forks a child that execs "sh -c '<shell_cmd>'".  The monitored pid
 * is only known, and can only be published to the BPF program, once
 * the child exists: the child waits on a pipe until the parent has
 * updated it.  Returns the child's exit status, or -1 on error.
 */
static int run_exec_child(struct lsm_policy_kfuncs_success *skel,
			  bool monitored, const char *shell_cmd)
{
	int pipe_fds[2], status;
	char buf = 0;
	pid_t pid;

	if (!ASSERT_OK(pipe(pipe_fds), "pipe"))
		return -1;

	pid = fork();
	if (!ASSERT_GE(pid, 0, "fork")) {
		close(pipe_fds[0]);
		close(pipe_fds[1]);
		return -1;
	}
	if (pid == 0) {
		char *argv[] = { "sh", "-c", (char *)shell_cmd, NULL };

		close(pipe_fds[1]);
		read(pipe_fds[0], &buf, 1);
		close(pipe_fds[0]);
		execv("/bin/sh", argv);
		exit(127);
	}
	close(pipe_fds[0]);
	skel->bss->monitored_pid = monitored ? pid : 0;
	write(pipe_fds[1], &buf, 1);
	close(pipe_fds[1]);

	if (!ASSERT_EQ(waitpid(pid, &status, 0), pid, "waitpid"))
		return -1;
	if (!ASSERT_TRUE(WIFEXITED(status), "child_exited"))
		return -1;
	return WEXITSTATUS(status);
}

/* Exit codes: 4 = unexpected write outcome, 0 = everything as
 * expected.
 */
static void format_child_cmd(char *cmd, size_t len, bool expect_write_ok,
			     const char *tmp_path)
{
	if (expect_write_ok)
		snprintf(cmd, len, "echo x > %s || exit 4; exit 0", tmp_path);
	else
		snprintf(cmd, len,
			 "if echo x > %s 2>/dev/null; then exit 4; fi; exit 0",
			 tmp_path);
}

static void test_restrict_binprm(void)
{
	struct lsm_policy_kfuncs_success *skel = NULL;
	char tmp_path[] = "/tmp/lsm_policy_kfuncs_XXXXXX";
	char cmd[256];
	int ruleset_fd, tmp_fd, ret;

	tmp_fd = mkstemp(tmp_path);
	if (!ASSERT_GE(tmp_fd, 0, "mkstemp"))
		return;
	close(tmp_fd);

	ruleset_fd = create_ruleset();
	if (ruleset_fd < 0) {
		if (errno == EOPNOTSUPP || errno == ENOSYS)
			test__skip();
		else
			ASSERT_GE(ruleset_fd, 0, "landlock_create_ruleset");
		goto out_unlink;
	}

	skel = lsm_policy_kfuncs_success__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		goto out;
	skel->bss->ruleset_fd = ruleset_fd;

	if (!ASSERT_OK(lsm_policy_kfuncs_success__attach(skel), "skel_attach"))
		goto out;

	if (load_ruleset_into_map(skel))
		goto out;

	/* Control: an unmonitored execution may write to the tmp file. */
	reset_prog_state(skel);
	format_child_cmd(cmd, sizeof(cmd), true, tmp_path);
	ret = run_exec_child(skel, false, cmd);
	if (!ASSERT_EQ(ret, 0, "control_child_exit"))
		goto out;
	ASSERT_FALSE(skel->bss->called, "control_not_monitored");

	/* A monitored execution starts landlocked: the ruleset handles
	 * LANDLOCK_ACCESS_FS_WRITE_FILE without any rule, so the write
	 * must fail.
	 */
	reset_prog_state(skel);
	format_child_cmd(cmd, sizeof(cmd), false, tmp_path);
	ret = run_exec_child(skel, true, cmd);
	if (!ASSERT_EQ(ret, 0, "restricted_child_exit"))
		goto out;
	ASSERT_TRUE(skel->bss->called, "lsm_prog_called");
	ASSERT_FALSE(skel->bss->no_ruleset, "ruleset_in_map");
	ASSERT_EQ(skel->bss->restrict_err, 0, "restrict_binprm");

	/* The audit log flags of landlock_restrict_self(2) apply too. */
	reset_prog_state(skel);
	skel->bss->kfunc_flags = LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON;
	format_child_cmd(cmd, sizeof(cmd), false, tmp_path);
	ret = run_exec_child(skel, true, cmd);
	if (!ASSERT_EQ(ret, 0, "log_flags_child_exit"))
		goto out;
	ASSERT_EQ(skel->bss->restrict_err, 0, "log_flags_restrict_binprm");

	/* LANDLOCK_RESTRICT_SELF_TSYNC targets the calling threads, not
	 * an execution: the kfunc must reject it and the execution must
	 * stay unrestricted.
	 */
	reset_prog_state(skel);
	skel->bss->kfunc_flags = LANDLOCK_RESTRICT_SELF_TSYNC;
	format_child_cmd(cmd, sizeof(cmd), true, tmp_path);
	ret = run_exec_child(skel, true, cmd);
	if (!ASSERT_EQ(ret, 0, "tsync_child_exit"))
		goto out;
	ASSERT_TRUE(skel->bss->called, "tsync_prog_called");
	ASSERT_EQ(skel->bss->restrict_err, -EINVAL, "tsync_rejected");

	/* A second call on the same execution replaces the staged
	 * domain (and releases the first one): the result is a single
	 * restriction, not an error.
	 */
	reset_prog_state(skel);
	skel->bss->double_call = true;
	format_child_cmd(cmd, sizeof(cmd), false, tmp_path);
	ret = run_exec_child(skel, true, cmd);
	if (!ASSERT_EQ(ret, 0, "double_child_exit"))
		goto out;
	ASSERT_EQ(skel->bss->restrict_err, 0, "double_restrict_first");
	ASSERT_EQ(skel->bss->restrict2_err, 0, "double_restrict_second");
out:
	lsm_policy_kfuncs_success__destroy(skel);
	close(ruleset_fd);
out_unlink:
	unlink(tmp_path);
}

/* Checks that a staged restriction is discarded, and the staged
 * domain released, when the execution fails after the bprm hook: the
 * calling task must not end up landlocked.
 */
static void test_restrict_binprm_discard(void)
{
	struct lsm_policy_kfuncs_success *skel = NULL;
	char tmp_path[] = "/tmp/lsm_policy_kfuncs_XXXXXX";
	char garbage_path[] = "/tmp/lsm_policy_garbage_XXXXXX";
	int ruleset_fd = -1, tmp_fd, garbage_fd, pipe_fds[2], status;
	char buf = 0;
	pid_t pid;

	tmp_fd = mkstemp(tmp_path);
	if (!ASSERT_GE(tmp_fd, 0, "mkstemp"))
		return;
	close(tmp_fd);

	/* An executable file that no binfmt handler accepts: the exec
	 * fails with ENOEXEC after bprm_creds_for_exec() has run.
	 */
	garbage_fd = mkstemp(garbage_path);
	if (!ASSERT_GE(garbage_fd, 0, "mkstemp_garbage"))
		goto out_unlink;
	if (!ASSERT_EQ(write(garbage_fd, "junk\n", 5), 5, "write_garbage")) {
		close(garbage_fd);
		goto out_unlink;
	}
	if (!ASSERT_OK(fchmod(garbage_fd, 0700), "chmod_garbage")) {
		close(garbage_fd);
		goto out_unlink;
	}
	close(garbage_fd);

	ruleset_fd = create_ruleset();
	if (ruleset_fd < 0) {
		if (errno == EOPNOTSUPP || errno == ENOSYS)
			test__skip();
		else
			ASSERT_GE(ruleset_fd, 0, "landlock_create_ruleset");
		goto out_unlink;
	}

	skel = lsm_policy_kfuncs_success__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		goto out;
	skel->bss->ruleset_fd = ruleset_fd;
	reset_prog_state(skel);

	if (!ASSERT_OK(lsm_policy_kfuncs_success__attach(skel), "skel_attach"))
		goto out;

	if (load_ruleset_into_map(skel))
		goto out;

	if (!ASSERT_OK(pipe(pipe_fds), "pipe"))
		goto out;

	pid = fork();
	if (!ASSERT_GE(pid, 0, "fork"))
		goto out;
	if (pid == 0) {
		char *argv[] = { "garbage", NULL };
		int fd;

		close(pipe_fds[1]);
		read(pipe_fds[0], &buf, 1);
		close(pipe_fds[0]);
		execv(garbage_path, argv);
		/* The failed execution must leave no trace: no
		 * Landlock domain, i.e. writing must still work
		 * (exit 6).
		 */
		fd = open(tmp_path, O_WRONLY | O_TRUNC);
		if (fd < 0)
			exit(6);
		close(fd);
		exit(0);
	}
	close(pipe_fds[0]);
	skel->bss->monitored_pid = pid;
	write(pipe_fds[1], &buf, 1);
	close(pipe_fds[1]);

	if (!ASSERT_EQ(waitpid(pid, &status, 0), pid, "waitpid"))
		goto out;
	if (!ASSERT_TRUE(WIFEXITED(status), "child_exited"))
		goto out;
	ASSERT_EQ(WEXITSTATUS(status), 0, "discard_child_exit");
	ASSERT_TRUE(skel->bss->called, "lsm_prog_called");
	ASSERT_EQ(skel->bss->restrict_err, 0, "restrict_binprm");
out:
	lsm_policy_kfuncs_success__destroy(skel);
	if (ruleset_fd >= 0)
		close(ruleset_fd);
out_unlink:
	unlink(garbage_path);
	unlink(tmp_path);
}

void test_lsm_policy_kfuncs(void)
{
	if (test__start_subtest("restrict_binprm"))
		test_restrict_binprm();
	if (test__start_subtest("restrict_binprm_discard"))
		test_restrict_binprm_discard();
	RUN_TESTS(lsm_policy_kfuncs_failure);
}
