// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE
#include <test_progs.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include "crib_files_failure.skel.h"
#include "crib_files_success.skel.h"

struct files_test_args {
	bool *setup_end;
	bool *cr_end;
};

static int files_test_process(void *args)
{
	struct files_test_args *test_args = (struct files_test_args *)args;
	int pipefd[2], sockfd, err = 0;

	/* Create a clean file descriptor table for the test process */
	close_range(0, ~0U, 0);

	if (pipe(pipefd) < 0)
		return 1;

	sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sockfd < 0) {
		err = 2;
		goto cleanup_pipe;
	}

	*test_args->setup_end = true;

	while (!*test_args->cr_end)
		;

	close(sockfd);
cleanup_pipe:
	close(pipefd[0]);
	close(pipefd[1]);
	return err;
}

static void run_files_success_test(const char *prog_name)
{
	int prog_fd, child_pid, wstatus, err = 0;
	const int stack_size = 1024 * 1024;
	struct crib_files_success *skel;
	struct files_test_args args;
	struct bpf_program *prog;
	bool setup_end, cr_end;
	char *stack;

	skel = crib_files_success__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	if (!ASSERT_OK(skel->bss->err, "pre_test_err"))
		goto cleanup_skel;

	prog = bpf_object__find_program_by_name(skel->obj, prog_name);
	if (!ASSERT_OK_PTR(prog, "find_program_by_name"))
		goto cleanup_skel;

	prog_fd = bpf_program__fd(prog);
	if (!ASSERT_GT(prog_fd, -1, "bpf_program__fd"))
		goto cleanup_skel;

	stack = (char *)malloc(stack_size);
	if (!ASSERT_OK_PTR(stack, "clone_stack"))
		return;

	setup_end = false;
	cr_end = false;

	args.setup_end = &setup_end;
	args.cr_end = &cr_end;

	/* Note that there is no CLONE_FILES */
	child_pid = clone(files_test_process, stack + stack_size, CLONE_VM | SIGCHLD, &args);
	if (!ASSERT_GT(child_pid, -1, "child_pid"))
		goto cleanup_stack;

	while (!setup_end)
		;

	skel->bss->pid = child_pid;

	err = bpf_prog_test_run_opts(prog_fd, NULL);
	if (!ASSERT_OK(err, "prog_test_run"))
		goto cleanup_stack;

	cr_end = true;

	if (!ASSERT_GT(waitpid(child_pid, &wstatus, 0), -1, "waitpid"))
		goto cleanup_stack;

	if (!ASSERT_OK(WEXITSTATUS(wstatus), "run_files_test_err"))
		goto cleanup_stack;

	ASSERT_OK(skel->bss->err, "run_files_test_failure");
cleanup_stack:
	free(stack);
cleanup_skel:
	crib_files_success__destroy(skel);
}

static const char * const files_success_tests[] = {
	"test_bpf_iter_task_file",
};

void test_crib(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(files_success_tests); i++) {
		if (!test__start_subtest(files_success_tests[i]))
			continue;

		run_files_success_test(files_success_tests[i]);
	}

	RUN_TESTS(crib_files_failure);
}
