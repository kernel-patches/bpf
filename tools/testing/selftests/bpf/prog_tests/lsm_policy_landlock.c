// SPDX-License-Identifier: GPL-2.0
/* Copyright © 2026 Justin Suess <utilityemal77@gmail.com> */

#include <test_progs.h>
#include <errno.h>
#include <linux/landlock.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "lsm_policy_landlock.skel.h"

/* Fallbacks for old system headers. */
#ifndef LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON
#define LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON (1U << 1)
#endif
#ifndef LANDLOCK_RESTRICT_SELF_TSYNC
#define LANDLOCK_RESTRICT_SELF_TSYNC (1U << 3)
#endif
#ifndef LANDLOCK_RESTRICT_SELF_NO_NEW_PRIVS
#define LANDLOCK_RESTRICT_SELF_NO_NEW_PRIVS (1U << 4)
#endif
#ifndef LSM_ID_LANDLOCK
#define LSM_ID_LANDLOCK 110 /* uapi/linux/lsm.h */
#endif

struct policy_test_env {
	struct lsm_policy_landlock *skel;
	char tmp_path[64];
	int tmp_fd;
	int ruleset_fd;
};

static int create_ruleset(void)
{
	const struct landlock_ruleset_attr attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_WRITE_FILE,
	};

	return syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr), 0);
}

static void reset_prog_state(struct lsm_policy_landlock *skel)
{
	skel->bss->called = false;
	skel->bss->no_policy = false;
	skel->bss->restrict_err = -1;
	skel->bss->restrict2_err = -1;
	skel->bss->restrict_ok_count = 0;
	skel->bss->kfunc_flags = 0;
	skel->bss->double_call = false;
	skel->bss->monitored_pid = 0;
	skel->bss->monitored_pid2 = 0;
	skel->bss->enforce_domain_id = 0;
	skel->bss->enforce_count = 0;
	skel->bss->enforce_complete = false;
	skel->bss->enforce_process_wide = false;
	skel->bss->enforce_no_new_privs = false;
}

/*
 * Runs the syscall program that acquires the ruleset from
 * @ruleset_fd, in the runner's fd table, and parks it in the map kptr
 * slot for the LSM program.
 */
static int load_ruleset_into_map(struct lsm_policy_landlock *skel)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err;

	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.load_policy),
				     &opts);
	if (!ASSERT_OK(err, "load_policy_run"))
		return -1;
	if (!ASSERT_OK(opts.retval, "load_policy_retval"))
		return -1;
	/* Landlock's type tag, read off the trusted kptr, is never 0. */
	ASSERT_NEQ(skel->bss->policy_type, 0, "policy_type_nonzero");
	/* The fd, not a kfunc argument, routed the call to Landlock. */
	ASSERT_EQ(skel->bss->policy_lsmid, LSM_ID_LANDLOCK, "policy_lsmid");
	return 0;
}

/*
 * Creates the target tmp file and the ruleset, loads and attaches the
 * skeleton, and parks the ruleset in the map.  Returns 0 on success;
 * on failure (or skip), the caller must still run teardown_env().
 */
static int setup_env(struct policy_test_env *env)
{
	env->skel = NULL;
	env->ruleset_fd = -1;
	strcpy(env->tmp_path, "/tmp/lsm_policy_landlock_XXXXXX");
	env->tmp_fd = mkstemp(env->tmp_path);
	if (!ASSERT_GE(env->tmp_fd, 0, "mkstemp"))
		return -1;

	env->ruleset_fd = create_ruleset();
	if (env->ruleset_fd < 0) {
		if (errno == EOPNOTSUPP || errno == ENOSYS)
			test__skip();
		else
			ASSERT_GE(env->ruleset_fd, 0,
				  "landlock_create_ruleset");
		return -1;
	}

	env->skel = lsm_policy_landlock__open_and_load();
	if (!ASSERT_OK_PTR(env->skel, "skel_open_and_load"))
		return -1;
	env->skel->bss->ruleset_fd = env->ruleset_fd;
	reset_prog_state(env->skel);

	if (!ASSERT_OK(lsm_policy_landlock__attach(env->skel),
		       "skel_attach"))
		return -1;

	return load_ruleset_into_map(env->skel);
}

static void teardown_env(struct policy_test_env *env)
{
	lsm_policy_landlock__destroy(env->skel);
	if (env->ruleset_fd >= 0)
		close(env->ruleset_fd);
	if (env->tmp_fd >= 0)
		close(env->tmp_fd);
	unlink(env->tmp_path);
}

/*
 * Forks a child that blocks on a pipe, then execs @path with @argv.
 * Returns the child's pid, or -1 on error.  @release_fd receives the
 * pipe's write end: release_exec_child() lets the child exec, after
 * its pid has been published to the BPF program.
 */
static pid_t spawn_exec_child(const char *path, char *const argv[],
			      int *release_fd)
{
	int pipe_fds[2];
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
		close(pipe_fds[1]);
		read(pipe_fds[0], &buf, 1);
		close(pipe_fds[0]);
		execv(path, argv);
		exit(127);
	}
	close(pipe_fds[0]);
	*release_fd = pipe_fds[1];
	return pid;
}

static void release_exec_child(int release_fd)
{
	char buf = 0;

	write(release_fd, &buf, 1);
	close(release_fd);
}

/* Returns the child's exit status, or -1 on error. */
static int wait_exec_child(pid_t pid)
{
	int status;

	if (!ASSERT_EQ(waitpid(pid, &status, 0), pid, "waitpid"))
		return -1;
	if (!ASSERT_TRUE(WIFEXITED(status), "child_exited"))
		return -1;
	return WEXITSTATUS(status);
}

static int run_exec_child(struct lsm_policy_landlock *skel,
			  bool monitored, const char *shell_cmd)
{
	char *argv[] = { "sh", "-c", (char *)shell_cmd, NULL };
	int release_fd;
	pid_t pid;

	pid = spawn_exec_child("/bin/sh", argv, &release_fd);
	if (pid < 0)
		return -1;
	skel->bss->monitored_pid = monitored ? pid : 0;
	release_exec_child(release_fd);
	return wait_exec_child(pid);
}

/*
 * Exit codes: 4 = unexpected write outcome, 0 = everything as
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
	struct policy_test_env env;
	struct lsm_policy_landlock *skel;
	char cmd[256];
	int ret;

	if (setup_env(&env))
		goto out;
	skel = env.skel;

	/* Control: an unmonitored execution may write to the tmp file. */
	reset_prog_state(skel);
	format_child_cmd(cmd, sizeof(cmd), true, env.tmp_path);
	ret = run_exec_child(skel, false, cmd);
	if (!ASSERT_EQ(ret, 0, "control_child_exit"))
		goto out;
	ASSERT_FALSE(skel->bss->called, "control_not_monitored");

	/*
	 * A monitored execution starts landlocked: the ruleset handles
	 * LANDLOCK_ACCESS_FS_WRITE_FILE without any rule, so the write
	 * must fail.
	 */
	reset_prog_state(skel);
	format_child_cmd(cmd, sizeof(cmd), false, env.tmp_path);
	ret = run_exec_child(skel, true, cmd);
	if (!ASSERT_EQ(ret, 0, "restricted_child_exit"))
		goto out;
	ASSERT_TRUE(skel->bss->called, "lsm_prog_called");
	ASSERT_FALSE(skel->bss->no_policy, "ruleset_in_map");
	ASSERT_EQ(skel->bss->restrict_err, 0, "restrict_binprm");

	/* The audit log flags of landlock_restrict_self(2) apply too. */
	reset_prog_state(skel);
	skel->bss->kfunc_flags = LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON;
	format_child_cmd(cmd, sizeof(cmd), false, env.tmp_path);
	ret = run_exec_child(skel, true, cmd);
	if (!ASSERT_EQ(ret, 0, "log_flags_child_exit"))
		goto out;
	ASSERT_EQ(skel->bss->restrict_err, 0, "log_flags_restrict_binprm");

	/*
	 * LANDLOCK_RESTRICT_SELF_TSYNC targets the calling threads, not
	 * an execution: the kfunc must reject it and the execution must
	 * stay unrestricted.
	 */
	reset_prog_state(skel);
	skel->bss->kfunc_flags = LANDLOCK_RESTRICT_SELF_TSYNC;
	format_child_cmd(cmd, sizeof(cmd), true, env.tmp_path);
	ret = run_exec_child(skel, true, cmd);
	if (!ASSERT_EQ(ret, 0, "tsync_child_exit"))
		goto out;
	ASSERT_TRUE(skel->bss->called, "tsync_prog_called");
	ASSERT_EQ(skel->bss->restrict_err, -EINVAL, "tsync_rejected");

	/*
	 * A second call on the same execution replaces the staged
	 * domain (and releases the first one): the result is a single
	 * restriction, not an error.
	 */
	reset_prog_state(skel);
	skel->bss->double_call = true;
	format_child_cmd(cmd, sizeof(cmd), false, env.tmp_path);
	ret = run_exec_child(skel, true, cmd);
	if (!ASSERT_EQ(ret, 0, "double_child_exit"))
		goto out;
	ASSERT_EQ(skel->bss->restrict_err, 0, "double_restrict_first");
	ASSERT_EQ(skel->bss->restrict2_err, 0, "double_restrict_second");
out:
	teardown_env(&env);
}

/*
 * Two monitored executions, released together, must both be
 * restricted from the one shared map kptr slot.
 */
static void test_restrict_binprm_concurrent(void)
{
	struct policy_test_env env;
	char *argv[4];
	int release_fds[2] = { -1, -1 };
	pid_t pids[2] = { -1, -1 };
	char cmd[256];
	int i;

	if (setup_env(&env))
		goto out;

	format_child_cmd(cmd, sizeof(cmd), false, env.tmp_path);
	argv[0] = "sh";
	argv[1] = "-c";
	argv[2] = cmd;
	argv[3] = NULL;

	for (i = 0; i < 2; i++) {
		pids[i] = spawn_exec_child("/bin/sh", argv, &release_fds[i]);
		if (pids[i] < 0)
			goto out_kill;
	}

	env.skel->bss->monitored_pid = pids[0];
	env.skel->bss->monitored_pid2 = pids[1];

	/* Releases both children only once both pids are published. */
	for (i = 0; i < 2; i++) {
		release_exec_child(release_fds[i]);
		release_fds[i] = -1;
	}

	for (i = 0; i < 2; i++) {
		ASSERT_EQ(wait_exec_child(pids[i]), 0,
			  "concurrent_child_exit");
		pids[i] = -1;
	}

	ASSERT_FALSE(env.skel->bss->no_policy, "ruleset_in_map");
	ASSERT_EQ(env.skel->bss->restrict_ok_count, 2,
		  "both_execs_restricted");

out_kill:
	for (i = 0; i < 2; i++) {
		if (pids[i] > 0) {
			kill(pids[i], SIGKILL);
			waitpid(pids[i], NULL, 0);
		}
		if (release_fds[i] >= 0)
			close(release_fds[i]);
	}
out:
	teardown_env(&env);
}

/*
 * Checks that a staged restriction is discarded, and the staged
 * domain released, when the execution fails after the bprm hook: the
 * calling task must not end up landlocked.
 */
static void test_restrict_binprm_discard(void)
{
	struct policy_test_env env;
	char garbage_path[] = "/tmp/lsm_policy_garbage_XXXXXX";
	int garbage_fd, pipe_fds[2];
	char buf = 0;
	pid_t pid;

	if (setup_env(&env))
		goto out;

	/*
	 * An executable file that no binfmt handler accepts: the exec
	 * fails with ENOEXEC after bprm_creds_for_exec() has run.
	 */
	garbage_fd = mkstemp(garbage_path);
	if (!ASSERT_GE(garbage_fd, 0, "mkstemp_garbage"))
		goto out;
	if (!ASSERT_EQ(write(garbage_fd, "junk\n", 5), 5, "write_garbage") ||
	    !ASSERT_OK(fchmod(garbage_fd, 0700), "chmod_garbage")) {
		close(garbage_fd);
		goto out_unlink;
	}
	close(garbage_fd);

	if (!ASSERT_OK(pipe(pipe_fds), "pipe"))
		goto out_unlink;

	/*
	 * Cannot use spawn_exec_child(): the same process must test its
	 * write access after the failed exec.
	 */
	pid = fork();
	if (!ASSERT_GE(pid, 0, "fork"))
		goto out_unlink;
	if (pid == 0) {
		char *argv[] = { "garbage", NULL };
		int fd;

		close(pipe_fds[1]);
		read(pipe_fds[0], &buf, 1);
		close(pipe_fds[0]);
		execv(garbage_path, argv);
		/*
		 * The failed execution must leave no trace: no
		 * Landlock domain, i.e. writing must still work
		 * (exit 6).
		 */
		fd = open(env.tmp_path, O_WRONLY | O_TRUNC);
		if (fd < 0)
			exit(6);
		close(fd);
		exit(0);
	}
	close(pipe_fds[0]);
	env.skel->bss->monitored_pid = pid;
	release_exec_child(pipe_fds[1]);

	ASSERT_EQ(wait_exec_child(pid), 0, "discard_child_exit");
	ASSERT_TRUE(env.skel->bss->called, "lsm_prog_called");
	ASSERT_EQ(env.skel->bss->restrict_err, 0, "restrict_binprm");
out_unlink:
	unlink(garbage_path);
out:
	teardown_env(&env);
}

/*
 * LANDLOCK_RESTRICT_SELF_NO_NEW_PRIVS makes the executed program start
 * with no_new_privs set; without it, a non-nnp parent's execution
 * stays non-nnp.  Child exit code 5: unexpected NoNewPrivs value.
 */
static void test_restrict_binprm_nnp(void)
{
	static const char nnp_cmd[] =
		"grep -q '^NoNewPrivs:[[:space:]]*%d' /proc/self/status || exit 5";
	struct policy_test_env env;
	struct lsm_policy_landlock *skel;
	char cmd[sizeof(nnp_cmd)];
	int ret;

	if (setup_env(&env))
		goto out;
	skel = env.skel;

	if (!ASSERT_OK(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0),
		       "runner_not_nnp"))
		goto out;

	reset_prog_state(skel);
	snprintf(cmd, sizeof(cmd), nnp_cmd, 0);
	ret = run_exec_child(skel, true, cmd);
	if (!ASSERT_EQ(ret, 0, "no_flag_child_exit"))
		goto out;
	ASSERT_EQ(skel->bss->restrict_err, 0, "no_flag_restrict_binprm");

	reset_prog_state(skel);
	skel->bss->kfunc_flags = LANDLOCK_RESTRICT_SELF_NO_NEW_PRIVS;
	snprintf(cmd, sizeof(cmd), nnp_cmd, 1);
	ret = run_exec_child(skel, true, cmd);
	if (!ASSERT_EQ(ret, 0, "nnp_flag_child_exit"))
		goto out;
	ASSERT_EQ(skel->bss->restrict_err, 0, "nnp_flag_restrict_binprm");
out:
	teardown_env(&env);
}

/*
 * The bprm application emits landlock_enforce_domain, observed here by
 * a tp_btf program: the single event concludes the operation
 * (complete == 1), covers the whole post-de_thread() process
 * (process_wide == 1), and reports the post-flag no_new_privs state.
 */
static void test_restrict_binprm_trace(void)
{
	struct policy_test_env env;
	struct lsm_policy_landlock *skel;
	char cmd[256];
	int ret;

	if (setup_env(&env))
		goto out;
	skel = env.skel;

	if (!ASSERT_OK(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0),
		       "runner_not_nnp"))
		goto out;

	reset_prog_state(skel);
	format_child_cmd(cmd, sizeof(cmd), false, env.tmp_path);
	ret = run_exec_child(skel, true, cmd);
	if (!ASSERT_EQ(ret, 0, "trace_child_exit"))
		goto out;
	ASSERT_EQ(skel->bss->restrict_err, 0, "restrict_binprm");
	ASSERT_EQ(skel->bss->enforce_count, 1, "one_enforce_event");
	ASSERT_TRUE(skel->bss->enforce_complete, "enforce_complete");
	ASSERT_TRUE(skel->bss->enforce_process_wide, "enforce_process_wide");
	ASSERT_NEQ(skel->bss->enforce_domain_id, 0, "enforce_domain_id");
	ASSERT_FALSE(skel->bss->enforce_no_new_privs, "enforce_nnp_off");

	reset_prog_state(skel);
	skel->bss->kfunc_flags = LANDLOCK_RESTRICT_SELF_NO_NEW_PRIVS;
	format_child_cmd(cmd, sizeof(cmd), false, env.tmp_path);
	ret = run_exec_child(skel, true, cmd);
	if (!ASSERT_EQ(ret, 0, "trace_nnp_child_exit"))
		goto out;
	ASSERT_EQ(skel->bss->enforce_count, 1, "one_enforce_event_nnp");
	ASSERT_TRUE(skel->bss->enforce_no_new_privs, "enforce_nnp_on");
out:
	teardown_env(&env);
}

void test_lsm_policy_landlock(void)
{
	if (test__start_subtest("restrict_binprm"))
		test_restrict_binprm();
	if (test__start_subtest("restrict_binprm_concurrent"))
		test_restrict_binprm_concurrent();
	if (test__start_subtest("restrict_binprm_discard"))
		test_restrict_binprm_discard();
	if (test__start_subtest("restrict_binprm_nnp"))
		test_restrict_binprm_nnp();
	if (test__start_subtest("restrict_binprm_trace"))
		test_restrict_binprm_trace();
}
