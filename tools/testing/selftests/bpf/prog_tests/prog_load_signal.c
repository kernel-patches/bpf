// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>

#define NOP_CNT		32768
#define MIN_KILL_DELAY_NS	(100ULL * 1000 * 1000)
#define REAP_TIMEOUT_NS		(1000ULL * 1000 * 1000)

static __u64 monotonic_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void sleep_ns(__u64 duration)
{
	struct timespec ts = {
		.tv_sec = duration / 1000000000ULL,
		.tv_nsec = duration % 1000000000ULL,
	};

	while (nanosleep(&ts, &ts) && errno == EINTR)
		;
}

static int waitpid_timeout(pid_t pid, int *status, __u64 timeout)
{
	__u64 deadline = monotonic_ns() + timeout;
	int ret;

	do {
		ret = waitpid(pid, status, WNOHANG);
		if (ret)
			return ret;
		usleep(1000);
	} while (monotonic_ns() < deadline);

	return 0;
}

void test_prog_load_signal(void)
{
	struct bpf_insn *insns = NULL;
	__u64 start, control_time, kill_delay;
	int pipefd[2] = { -1, -1 };
	int prog_fd = -1, status = 0;
	pid_t pid = -1;
	char byte;
	int i, ret;

	insns = calloc(NOP_CNT + 2, sizeof(*insns));
	if (!ASSERT_OK_PTR(insns, "calloc"))
		return;

	for (i = 0; i < NOP_CNT; i++)
		insns[i] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_1);
	insns[NOP_CNT] = BPF_MOV64_IMM(BPF_REG_0, 0);
	insns[NOP_CNT + 1] = BPF_EXIT_INSN();

	start = monotonic_ns();
	prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, NULL, "GPL",
				insns, NOP_CNT + 2, NULL);
	control_time = monotonic_ns() - start;
	if (!ASSERT_GE(prog_fd, 0, "control_prog_load"))
		goto cleanup;
	close(prog_fd);
	prog_fd = -1;

	for (i = 0; i < NOP_CNT; i++)
		insns[i] = BPF_JMP_IMM(BPF_JA, 0, 0, 0);

	if (!ASSERT_OK(pipe(pipefd), "pipe"))
		goto cleanup;

	pid = fork();
	if (!ASSERT_GE(pid, 0, "fork"))
		goto cleanup;
	if (!pid) {
		close(pipefd[0]);
		if (write(pipefd[1], "x", 1) != 1)
			_exit(1);
		close(pipefd[1]);
		prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, NULL, "GPL",
					insns, NOP_CNT + 2, NULL);
		if (prog_fd >= 0)
			close(prog_fd);
		_exit(prog_fd < 0);
	}

	close(pipefd[1]);
	pipefd[1] = -1;
	ret = read(pipefd[0], &byte, 1);
	if (!ASSERT_EQ(ret, 1, "child_ready"))
		goto cleanup;

	/*
	 * Allow linear verification to finish before sending SIGKILL. The nop
	 * removal pass is quadratic, so four control-load times still leaves a
	 * wide window in which an affected kernel is rewriting instructions.
	 */
	kill_delay = MAX(control_time * 4, MIN_KILL_DELAY_NS);
	sleep_ns(kill_delay);
	if (!ASSERT_OK(kill(pid, SIGKILL), "kill"))
		goto cleanup;

	start = monotonic_ns();
	ret = waitpid_timeout(pid, &status, REAP_TIMEOUT_NS);
	if (!ASSERT_EQ(ret, pid, "prog_load_killable")) {
		fprintf(stderr, "control load %llu us, child still alive %llu us after SIGKILL\n",
			control_time / 1000, (monotonic_ns() - start) / 1000);
		goto cleanup;
	}
	pid = -1;
	ASSERT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL,
		    "killed_by_sigkill");

cleanup:
	if (prog_fd >= 0)
		close(prog_fd);
	if (pipefd[0] >= 0)
		close(pipefd[0]);
	if (pipefd[1] >= 0)
		close(pipefd[1]);
	if (pid > 0) {
		kill(pid, SIGKILL);
		waitpid(pid, &status, 0);
	}
	free(insns);
}
