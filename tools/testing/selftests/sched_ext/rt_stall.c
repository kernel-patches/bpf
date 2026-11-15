// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2025 NVIDIA Corporation.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <linux/sched.h>
#include <signal.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "rt_stall.bpf.skel.h"
#include "scx_test.h"

#define CORE_ID		0	/* CPU to pin tasks to */
#define RUN_TIME        5	/* How long to run the test in seconds */

static cpu_set_t old_mask;
static bool affinity_saved;

/* Signal the parent that setup is complete by writing to a pipe */
static void signal_ready(int fd)
{
	char c = 1;

	if (write(fd, &c, 1) != 1) {
		perror("write to ready pipe");
		exit(EXIT_FAILURE);
	}
	close(fd);
}

/* Wait for a child to signal readiness via a pipe */
static bool wait_ready(int fd)
{
	bool ready;
	char c;

	ready = read(fd, &c, 1) == 1;
	if (!ready)
		perror("read from ready pipe");
	close(fd);

	return ready;
}

/* Simple busy-wait function for test tasks */
static void process_func(void)
{
	while (1) {
		/* Busy wait */
		for (volatile unsigned long i = 0; i < 10000000UL; i++)
			;
	}
}

/* Set CPU affinity to a specific core */
static void set_affinity(int cpu)
{
	cpu_set_t mask;

	CPU_ZERO(&mask);
	CPU_SET(cpu, &mask);
	if (sched_setaffinity(0, sizeof(mask), &mask) != 0) {
		perror("sched_setaffinity");
		exit(EXIT_FAILURE);
	}
}

/* Set task scheduling policy and priority */
static void set_sched(int policy, int priority)
{
	struct sched_param param;

	param.sched_priority = priority;
	if (sched_setscheduler(0, policy, &param) != 0) {
		perror("sched_setscheduler");
		exit(EXIT_FAILURE);
	}
}

/* Get process runtime from CPU clock */
static float get_process_runtime(int pid)
{
	clockid_t clk;
	struct timespec ts;
	int err;

	err = clock_getcpuclockid(pid, &clk);
	if (err) {
		fprintf(stderr, "Failed to get clock ID: %s\n", strerror(err));
		return -1;
	}

	if (clock_gettime(clk, &ts) == -1) {
		perror("Failed to get clock time");
		return -1;
	}

	return ts.tv_sec + ts.tv_nsec / 1e9;
}

/* Move parent off of CORE_ID so it doesn't share DL server budget */
static int pin_parent_off_core(void)
{
	if (sched_getaffinity(0, sizeof(old_mask), &old_mask) != 0) {
		perror("sched_getaffinity");
		return -1;
	}

	for (int cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		if (CPU_ISSET(cpu, &old_mask) && cpu != CORE_ID) {
			cpu_set_t mask;

			CPU_ZERO(&mask);
			CPU_SET(cpu, &mask);
			if (sched_setaffinity(0, sizeof(mask), &mask)) {
				perror("sched_setaffinity");
				return -1;
			}
			affinity_saved = true;
			return 0;
		}
	}

	return 1; /* No other CPU available */
}

static enum scx_test_status setup(void **ctx)
{
	struct rt_stall *skel;
	int err;

	if (!__COMPAT_struct_has_field("rq", "ext_server")) {
		fprintf(stderr, "SKIP: ext DL server not supported\n");
		return SCX_TEST_SKIP;
	}

	skel = rt_stall__open();
	SCX_FAIL_IF(!skel, "Failed to open");
	SCX_ENUM_INIT(skel);
	SCX_FAIL_IF(rt_stall__load(skel), "Failed to load skel");

	*ctx = skel;

	err = pin_parent_off_core();
	SCX_FAIL_IF(err == -1, "Failed to pin parent CPU");

	return SCX_TEST_PASS;
}

static bool sched_stress_test(bool is_ext)
{
	/*
	 * We're expecting the EXT task to get around 5% of CPU time when
	 * competing with the RT task (small 1% fluctuations are expected).
	 *
	 * However, the EXT task should get at least 4% of the CPU to prove
	 * that the EXT deadline server is working correctly. A percentage
	 * less than 4% indicates a bug where RT tasks can potentially
	 * stall SCHED_EXT tasks, causing the test to fail.
	 *
	 * The DL server budget is per-CPU and shared with all other
	 * EXT/FAIR tasks on CORE_ID (e.g., kthreads, ksoftirqd). The EXT
	 * task may get slightly less than 5% on a noisy system due to this.
	 */
	const float expected_min_ratio = 0.04; /* 4% */
	const char *class_str = is_ext ? "EXT" : "FAIR";

	float ext_runtime_start, rt_runtime_start, ext_runtime, rt_runtime, actual_ratio;
	int ext_pid, rt_pid;
	int ext_ready[2], rt_ready[2];
	bool ret = false;

	if (pipe(ext_ready) || pipe(rt_ready)) {
		perror("pipe");
		return false;
	}

	/* Create and set up a EXT task */
	ext_pid = fork();
	if (ext_pid == 0) {
		close(ext_ready[0]);
		close(rt_ready[0]);
		close(rt_ready[1]);
		set_affinity(CORE_ID);
		signal_ready(ext_ready[1]);
		process_func();
		exit(0);
	} else if (ext_pid < 0) {
		perror("fork task");
		return false;
	}

	/* Create an RT task */
	rt_pid = fork();
	if (rt_pid == 0) {
		close(ext_ready[0]);
		close(ext_ready[1]);
		close(rt_ready[0]);
		set_affinity(CORE_ID);
		set_sched(SCHED_FIFO, 50);
		signal_ready(rt_ready[1]);
		process_func();
		exit(0);
	} else if (rt_pid < 0) {
		perror("fork for RT task");
		goto out_kill_ext;
	}

	/*
	 * Wait for both children to complete their setup (affinity and
	 * scheduling policy) before starting the measurement window.
	 * This prevents flaky failures caused by the RT child's setup
	 * time eating into the measurement period.
	 */
	close(ext_ready[1]);
	close(rt_ready[1]);
	if (!wait_ready(ext_ready[0]) || !wait_ready(rt_ready[0]))
		goto out_kill;

	/*
	 * The parent can be delayed before reaching sleep(). Record each task's
	 * CPU time right before calling sleep() so only time used during the
	 * measurement window is counted.
	 */
	ext_runtime_start = get_process_runtime(ext_pid);
	if (ext_runtime_start == -1) {
		fprintf(stderr, "Failed to read %s task runtime\n", class_str);
		goto out_kill;
	}

	rt_runtime_start = get_process_runtime(rt_pid);
	if (rt_runtime_start == -1) {
		fprintf(stderr, "Failed to read RT task runtime\n");
		goto out_kill;
	}

	/* Let the processes run for the specified time */
	sleep(RUN_TIME);

	/* Get runtime for the EXT task */
	ext_runtime = get_process_runtime(ext_pid);
	if (ext_runtime == -1) {
		fprintf(stderr, "Failed to read %s task runtime\n", class_str);
		goto out_kill;
	}

	/* Get runtime for the RT task */
	rt_runtime = get_process_runtime(rt_pid);
	if (rt_runtime == -1) {
		fprintf(stderr, "Failed to read RT task runtime\n");
		goto out_kill;
	}

	ext_runtime = ext_runtime - ext_runtime_start;
	rt_runtime = rt_runtime - rt_runtime_start;
	/* Verify that the scx task got enough runtime */
	actual_ratio = ext_runtime / (ext_runtime + rt_runtime);
	fprintf(stderr, "%s task ran %.3fs, RT task ran %.3fs (%.2f%% of runtime)\n",
		class_str, ext_runtime, rt_runtime, actual_ratio * 100);

	if (actual_ratio < expected_min_ratio) {
		fprintf(stderr, "%s task got less than %.2f%% of runtime\n",
			class_str, expected_min_ratio * 100);
		goto out_kill;
	}

	ret = true;

out_kill:
	kill(rt_pid, SIGKILL);
	waitpid(rt_pid, NULL, 0);
out_kill_ext:
	kill(ext_pid, SIGKILL);
	waitpid(ext_pid, NULL, 0);

	return ret;
}

static enum scx_test_status run(void *ctx)
{
	struct rt_stall *skel = ctx;
	struct bpf_link *link = NULL;
	bool res;
	int i;

	/*
	 * Test if the dl_server is working both with and without the
	 * sched_ext scheduler attached.
	 *
	 * This ensures all the scenarios are covered:
	 *   - fair_server stop -> ext_server start
	 *   - ext_server stop -> fair_server stop
	 */
	for (i = 0; i < 4; i++) {
		bool is_ext = i % 2;

		if (is_ext) {
			memset(&skel->data->uei, 0, sizeof(skel->data->uei));
			link = bpf_map__attach_struct_ops(skel->maps.rt_stall_ops);
			SCX_FAIL_IF(!link, "Failed to attach scheduler");
		}

		res = sched_stress_test(is_ext);

		if (is_ext) {
			int exit_kind = skel->data->uei.kind;
			bpf_link__destroy(link);
			SCX_EQ(exit_kind, EXIT_KIND(SCX_EXIT_NONE));
		}

		if (!res)
			return SCX_TEST_FAIL;
	}

	return SCX_TEST_PASS;
}

static void cleanup(void *ctx)
{
	struct rt_stall *skel = ctx;

	if (affinity_saved)
		sched_setaffinity(0, sizeof(old_mask), &old_mask);

	rt_stall__destroy(skel);
}

struct scx_test rt_stall = {
	.name = "rt_stall",
	.description = "Verify that RT tasks cannot stall SCHED_EXT tasks",
	.setup = setup,
	.run = run,
	.cleanup = cleanup,
};
REGISTER_SCX_TEST(&rt_stall)
