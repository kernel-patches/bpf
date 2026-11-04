// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */
#include <signal.h>
#include <sys/syscall.h>
#include <test_progs.h>

#include "test_build_id.skel.h"

static char build_id[BPF_BUILD_ID_SIZE];
static int build_id_sz;

static void print_stack(struct bpf_stack_build_id *stack, int frame_cnt)
{
	int i, j;

	for (i = 0; i < frame_cnt; i++) {
		printf("FRAME #%02d: ", i);
		switch (stack[i].status) {
		case BPF_STACK_BUILD_ID_EMPTY:
			printf("<EMPTY>\n");
			break;
		case BPF_STACK_BUILD_ID_VALID:
			printf("BUILD ID = ");
			for (j = 0; j < BPF_BUILD_ID_SIZE; j++)
				printf("%02hhx", (unsigned)stack[i].build_id[j]);
			printf(" OFFSET = %llx", (unsigned long long)stack[i].offset);
			break;
		case BPF_STACK_BUILD_ID_IP:
			printf("IP = %llx", (unsigned long long)stack[i].ip);
			break;
		default:
			printf("UNEXPECTED STATUS %d ", stack[i].status);
			break;
		}
		printf("\n");
	}
}

static void subtest_nofault(bool build_id_resident)
{
	struct test_build_id *skel;
	struct bpf_stack_build_id *stack;
	int frame_cnt;

	skel = test_build_id__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	skel->links.uprobe_nofault = bpf_program__attach(skel->progs.uprobe_nofault);
	if (!ASSERT_OK_PTR(skel->links.uprobe_nofault, "link"))
		goto cleanup;

	if (build_id_resident)
		ASSERT_OK(system("./uprobe_multi uprobe-paged-in"), "trigger_uprobe");
	else
		ASSERT_OK(system("./uprobe_multi uprobe-paged-out"), "trigger_uprobe");

	if (!ASSERT_GT(skel->bss->res_nofault, 0, "res"))
		goto cleanup;

	stack = skel->bss->stack_nofault;
	frame_cnt = skel->bss->res_nofault / sizeof(struct bpf_stack_build_id);
	if (env.verbosity >= VERBOSE_NORMAL)
		print_stack(stack, frame_cnt);

	if (build_id_resident) {
		ASSERT_EQ(stack[0].status, BPF_STACK_BUILD_ID_VALID, "build_id_status");
		ASSERT_EQ(memcmp(stack[0].build_id, build_id, build_id_sz), 0, "build_id_match");
	} else {
		ASSERT_EQ(stack[0].status, BPF_STACK_BUILD_ID_IP, "build_id_status");
	}

cleanup:
	test_build_id__destroy(skel);
}

static void subtest_sleepable(void)
{
	struct test_build_id *skel;
	struct bpf_stack_build_id *stack;
	int frame_cnt;

	skel = test_build_id__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	skel->links.uprobe_sleepable = bpf_program__attach(skel->progs.uprobe_sleepable);
	if (!ASSERT_OK_PTR(skel->links.uprobe_sleepable, "link"))
		goto cleanup;

	/* force build ID to not be paged in */
	ASSERT_OK(system("./uprobe_multi uprobe-paged-out"), "trigger_uprobe");

	if (!ASSERT_GT(skel->bss->res_sleepable, 0, "res"))
		goto cleanup;

	stack = skel->bss->stack_sleepable;
	frame_cnt = skel->bss->res_sleepable / sizeof(struct bpf_stack_build_id);
	if (env.verbosity >= VERBOSE_NORMAL)
		print_stack(stack, frame_cnt);

	ASSERT_EQ(stack[0].status, BPF_STACK_BUILD_ID_VALID, "build_id_status");
	ASSERT_EQ(memcmp(stack[0].build_id, build_id, build_id_sz), 0, "build_id_match");

cleanup:
	test_build_id__destroy(skel);
}

static bool stack_has_build_id(const struct bpf_stack_build_id *stack, int frame_cnt,
			       const char *id, int id_sz)
{
	int i;

	for (i = 0; i < frame_cnt; i++)
		if (stack[i].status == BPF_STACK_BUILD_ID_VALID &&
		    !memcmp(stack[i].build_id, id, id_sz))
			return true;

	return false;
}

/*
 * Run uprobe_multi, let it page out the build ID page and stop itself on
 * SIGSTOP, so that the recorded stack cannot be overwritten by a later
 * syscall while the caller inspects it.  target_tgid is set before the
 * child is released, so only its syscalls are recorded.
 */
static int run_uprobe_multi_stopped(const char *mode, struct test_build_id *skel,
				    pid_t *pid_out)
{
	char c = 'x';
	int pfd[2], status, err;
	pid_t pid;

	*pid_out = -1;

	if (pipe(pfd))
		return -errno;

	pid = fork();
	if (pid < 0) {
		err = -errno;
		close(pfd[0]);
		close(pfd[1]);
		return err;
	}
	if (pid == 0) {
		close(pfd[1]);
		if (read(pfd[0], &c, 1) != 1)
			_exit(127);
		close(pfd[0]);
		execl("./uprobe_multi", "uprobe_multi", mode, NULL);
		_exit(127);
	}

	close(pfd[0]);
	skel->bss->target_tgid = pid;
	skel->bss->target_syscall = SYS_getpid;
	if (write(pfd[1], &c, 1) != 1) {
		err = -errno;
		close(pfd[1]);
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		return err;
	}
	close(pfd[1]);

	if (waitpid(pid, &status, WUNTRACED) < 0) {
		err = -errno;
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		return err;
	}

	if (WIFSTOPPED(status)) {
		*pid_out = pid;
		return 0;
	}
	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	return -1;
}

static void subtest_raw_tp(bool sleepable)
{
	struct test_build_id *skel;
	struct bpf_stack_build_id *stack;
	int frame_cnt, err, res;
	pid_t pid = -1;

	skel = test_build_id__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	if (sleepable) {
		skel->links.rawtp_sleepable = bpf_program__attach(skel->progs.rawtp_sleepable);
		if (!ASSERT_OK_PTR(skel->links.rawtp_sleepable, "attach_rawtp_sleepable"))
			goto cleanup;
	} else {
		skel->links.rawtp_nofault = bpf_program__attach(skel->progs.rawtp_nofault);
		if (!ASSERT_OK_PTR(skel->links.rawtp_nofault, "attach_rawtp_nofault"))
			goto cleanup;
	}

	err = run_uprobe_multi_stopped("uprobe-paged-out-stop", skel, &pid);
	if (err == 2) {
		/* could not evict the build ID page, nothing to test */
		test__skip();
		goto cleanup;
	}
	if (!ASSERT_OK(err, "trigger_uprobe_multi"))
		goto cleanup;

	if (sleepable) {
		res = skel->bss->res_rawtp_sleepable;
		stack = skel->bss->stack_rawtp_sleepable;
	} else {
		res = skel->bss->res_rawtp_nofault;
		stack = skel->bss->stack_rawtp_nofault;
	}
	frame_cnt = res / sizeof(struct bpf_stack_build_id);
	if (env.verbosity >= VERBOSE_NORMAL)
		print_stack(stack, frame_cnt);

	ASSERT_GT(frame_cnt, 0, "frames");
	if (sleepable)
		ASSERT_TRUE(stack_has_build_id(stack, frame_cnt, build_id, build_id_sz),
			    "sleepable_build_id");
	else
		ASSERT_FALSE(stack_has_build_id(stack, frame_cnt, build_id, build_id_sz),
			     "nofault_build_id");

cleanup:
	if (pid > 0) {
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
	}
	test_build_id__destroy(skel);
}

void serial_test_build_id(void)
{
	build_id_sz = read_build_id("uprobe_multi", build_id, sizeof(build_id));
	ASSERT_EQ(build_id_sz, BPF_BUILD_ID_SIZE, "parse_build_id");

	if (test__start_subtest("nofault-paged-out"))
		subtest_nofault(false /* not resident */);
	if (test__start_subtest("nofault-paged-in"))
		subtest_nofault(true /* resident */);
	if (test__start_subtest("sleepable"))
		subtest_sleepable();
	if (test__start_subtest("raw-tp-nofault-paged-out"))
		subtest_raw_tp(false /* non-sleepable */);
	if (test__start_subtest("raw-tp-sleepable-paged-out"))
		subtest_raw_tp(true /* sleepable */);
}
