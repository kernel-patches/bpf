// SPDX-License-Identifier: GPL-2.0
/*
 * Verify that core-scheduling forced idle does not starve the fair deadline
 * server.
 *
 * A CPU is forced idle when it has runnable tasks of its own but its SMT
 * sibling runs a task with an incompatible core-sched cookie. If that time is
 * charged to the rq's deferred DL servers, the fair server's runtime drains
 * while it is throttled, its activation is pushed out every period, and the
 * CFS tasks it reserves bandwidth for get next to nothing.
 *
 * The test pins a cookied SCHED_FIFO spinner to one SMT sibling and an
 * uncookied CFS spinner to the other, so the second sibling is forced idle
 * whenever the FIFO task runs, and checks that the CFS task still gets a
 * sensible fraction of the fair server's reservation.
 *
 * Copyright (c) 2026 Amazon.com, Inc. or its affiliates.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../kselftest.h"

#ifndef PR_SCHED_CORE
#define PR_SCHED_CORE			62
#define PR_SCHED_CORE_GET		0
#define PR_SCHED_CORE_CREATE		1 /* create unique core_sched cookie */
#define PR_SCHED_CORE_SHARE_TO		2 /* push core_sched cookie to pid */
#define PR_SCHED_CORE_SHARE_FROM	3 /* pull core_sched cookie to pid */
#define PR_SCHED_CORE_MAX		4
#endif

enum pid_type {PIDTYPE_PID = 0, PIDTYPE_TGID, PIDTYPE_PGID};

#define SIBLINGS_LIST	"/sys/devices/system/cpu/cpu0/topology/thread_siblings_list"
#define FAIR_SERVER	"/sys/kernel/debug/sched/fair_server"

#define RUN_TIME	5	/* measurement window, in seconds */
#define FIFO_PRIO	50

/*
 * The reservation is only approached, not reached: every slice the fair server
 * gets costs the sibling a forced-idle hand-over, and the core-wide pick runs
 * at tick granularity. Ask for half of it, which is far above the few hundredths
 * of a percent a starved server leaves.
 */
#define MIN_SHARE_OF_RESERVATION	0.5

/* Status a spinner child reports to the parent over its readiness pipe. */
#define CHILD_READY	'R'
#define CHILD_EPERM	'P'
#define CHILD_ERROR	'E'

/* Tell the parent how setup went; it decides whether to run or to skip. */
static void signal_status(int fd, char status)
{
	if (write(fd, &status, 1) != 1) {
		ksft_perror("write to readiness pipe");
		exit(1);
	}
	if (status != CHILD_READY)
		exit(1);
}

/*
 * Burn CPU until killed. A constant controlling expression keeps the compiler
 * from removing the loop, so no volatile is needed to hold it in place.
 */
static void spin_forever(void)
{
	while (1)
		;
}

static int set_affinity(int cpu)
{
	cpu_set_t mask;

	CPU_ZERO(&mask);
	CPU_SET(cpu, &mask);

	return sched_setaffinity(0, sizeof(mask), &mask);
}

/*
 * Read the first two distinct CPU ids out of a cpu list such as "0-1", "0,4"
 * or "0,4-5". Returns 0 on success, -1 if the list holds fewer than two ids.
 */
static int parse_sibling_pair(const char *list, int *sib0, int *sib1)
{
	int found = 0, sib[2] = { -1, -1 };
	const char *p = list;

	while (*p && found < 2) {
		int first, last, n = 0;

		if (sscanf(p, "%d-%d%n", &first, &last, &n) != 2) {
			if (sscanf(p, "%d%n", &first, &n) != 1)
				return -1;
			last = first;
		}
		for (; first <= last && found < 2; first++)
			sib[found++] = first;
		p += n;
		if (*p != ',')
			break;
		p++;
	}

	if (found < 2)
		return -1;

	*sib0 = sib[0];
	*sib1 = sib[1];

	return 0;
}

static int read_sibling_pair(int *sib0, int *sib1)
{
	char list[256];
	FILE *f;
	char *s;

	f = fopen(SIBLINGS_LIST, "r");
	if (!f)
		return -1;
	s = fgets(list, sizeof(list), f);
	fclose(f);
	if (!s)
		return -1;

	return parse_sibling_pair(list, sib0, sib1);
}

static int read_u64_file(const char *path, unsigned long long *val)
{
	FILE *f;
	int ret;

	f = fopen(path, "r");
	if (!f)
		return -1;
	ret = fscanf(f, "%llu", val);
	fclose(f);

	return ret == 1 ? 0 : -1;
}

/* Read the fair server reservation of @cpu, in nanoseconds. */
static int read_fair_server(int cpu, unsigned long long *runtime,
			    unsigned long long *period)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), FAIR_SERVER "/cpu%d/runtime", cpu);
	if (read_u64_file(path, runtime))
		return -1;

	snprintf(path, sizeof(path), FAIR_SERVER "/cpu%d/period", cpu);
	if (read_u64_file(path, period))
		return -1;

	return 0;
}

/* CPU time consumed by @pid so far, in seconds, from /proc/<pid>/stat. */
static double process_runtime(pid_t pid)
{
	char path[PATH_MAX];
	unsigned long utime, stime;
	FILE *f;
	int fields;

	snprintf(path, sizeof(path), "/proc/%d/stat", pid);
	f = fopen(path, "r");
	if (!f)
		return -1;

	/* Skip the first 13 fields and read the 14th and 15th. */
	fields = fscanf(f, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu",
			&utime, &stime);
	fclose(f);
	if (fields != 2)
		return -1;

	return (double)(utime + stime) / sysconf(_SC_CLK_TCK);
}

static double monotonic_now(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		return -1;

	return ts.tv_sec + ts.tv_nsec / 1000000000.0;
}

/*
 * Diagnostic only: how long the FIFO task's CPU was forced idle. Needs
 * CONFIG_SCHEDSTATS and schedstats enabled, so it must not gate the result.
 */
static void print_forced_idle(pid_t pid)
{
	char path[PATH_MAX], line[256];
	FILE *f;

	snprintf(path, sizeof(path), "/proc/%d/sched", pid);
	f = fopen(path, "r");
	if (!f)
		return;

	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, "core_forceidle_sum")) {
			line[strcspn(line, "\n")] = '\0';
			ksft_print_msg("FIFO task %s\n", line);
			break;
		}
	}
	fclose(f);
}

/* Cookied SCHED_FIFO spinner. Only this task gets a cookie. */
static void fifo_child(int cpu, int ready_fd)
{
	struct sched_param param = { .sched_priority = FIFO_PRIO };

	if (set_affinity(cpu)) {
		ksft_perror("FIFO child sched_setaffinity");
		signal_status(ready_fd, CHILD_ERROR);
	}
	if (prctl(PR_SCHED_CORE, PR_SCHED_CORE_CREATE, 0, PIDTYPE_PID, 0)) {
		ksft_perror("FIFO child PR_SCHED_CORE_CREATE");
		signal_status(ready_fd, CHILD_ERROR);
	}
	if (sched_setscheduler(0, SCHED_FIFO, &param)) {
		if (errno == EPERM)
			signal_status(ready_fd, CHILD_EPERM);
		ksft_perror("FIFO child sched_setscheduler");
		signal_status(ready_fd, CHILD_ERROR);
	}
	signal_status(ready_fd, CHILD_READY);
	spin_forever();
}

/* Uncookied CFS spinner on the FIFO task's SMT sibling. */
static void cfs_child(int cpu, int ready_fd)
{
	if (set_affinity(cpu)) {
		ksft_perror("CFS child sched_setaffinity");
		signal_status(ready_fd, CHILD_ERROR);
	}
	signal_status(ready_fd, CHILD_READY);
	spin_forever();
}

static char wait_ready(int fd)
{
	char status;

	if (read(fd, &status, 1) != 1) {
		ksft_perror("read from readiness pipe");
		return CHILD_ERROR;
	}

	return status;
}

static void kill_child(pid_t *pid)
{
	if (*pid <= 0)
		return;
	kill(*pid, SIGKILL);
	waitpid(*pid, NULL, 0);
	*pid = -1;
}

int main(void)
{
	double fifo_runtime, cfs_start, cfs_end, t_start, t_end, share, want;
	unsigned long long runtime, period;
	pid_t fifo_pid = -1, cfs_pid = -1;
	int fifo_ready[2], cfs_ready[2];
	unsigned long long cookie;
	int sib0, sib1;
	char status;

	ksft_print_header();
	ksft_set_plan(1);

	if (read_sibling_pair(&sib0, &sib1)) {
		ksft_test_result_skip("CPU0 has no SMT sibling\n");
		ksft_finished();
	}
	ksft_print_msg("SMT siblings: CPU%d (FIFO) and CPU%d (CFS)\n", sib0, sib1);

	if (prctl(PR_SCHED_CORE, PR_SCHED_CORE_GET, 0, PIDTYPE_PID,
		  (unsigned long)&cookie)) {
		ksft_test_result_skip("core scheduling unavailable: %s\n",
				      strerror(errno));
		ksft_finished();
	}

	if (read_fair_server(sib1, &runtime, &period)) {
		ksft_test_result_skip("cannot read " FAIR_SERVER "/cpu%d, debugfs not mounted?\n",
				      sib1);
		ksft_finished();
	}
	if (!runtime || !period) {
		ksft_test_result_skip("fair server on CPU%d is disabled (%llu/%llu)\n",
				      sib1, runtime, period);
		ksft_finished();
	}
	ksft_print_msg("CPU%d fair server reservation: %llu/%llu ns = %.3f%%\n",
		       sib1, runtime, period, 100.0 * runtime / period);

	if (pipe(fifo_ready) || pipe(cfs_ready))
		ksft_exit_fail_perror("pipe");

	fifo_pid = fork();
	if (!fifo_pid) {
		close(fifo_ready[0]);
		close(cfs_ready[0]);
		close(cfs_ready[1]);
		fifo_child(sib0, fifo_ready[1]);
	} else if (fifo_pid < 0) {
		ksft_exit_fail_perror("fork FIFO child");
	}
	close(fifo_ready[1]);

	status = wait_ready(fifo_ready[0]);
	close(fifo_ready[0]);
	if (status != CHILD_READY) {
		kill_child(&fifo_pid);
		close(cfs_ready[0]);
		close(cfs_ready[1]);
		if (status == CHILD_EPERM) {
			ksft_test_result_skip("need privileges for SCHED_FIFO\n");
			ksft_finished();
		}
		ksft_exit_fail_msg("FIFO child setup failed\n");
	}

	cfs_pid = fork();
	if (!cfs_pid) {
		close(cfs_ready[0]);
		cfs_child(sib1, cfs_ready[1]);
	} else if (cfs_pid < 0) {
		kill_child(&fifo_pid);
		ksft_exit_fail_perror("fork CFS child");
	}
	close(cfs_ready[1]);

	status = wait_ready(cfs_ready[0]);
	close(cfs_ready[0]);
	if (status != CHILD_READY) {
		kill_child(&cfs_pid);
		kill_child(&fifo_pid);
		ksft_exit_fail_msg("CFS child setup failed\n");
	}

	cfs_start = process_runtime(cfs_pid);
	t_start = monotonic_now();
	sleep(RUN_TIME);
	t_end = monotonic_now();
	cfs_end = process_runtime(cfs_pid);
	fifo_runtime = process_runtime(fifo_pid);

	print_forced_idle(fifo_pid);
	kill_child(&cfs_pid);
	kill_child(&fifo_pid);

	if (cfs_start < 0 || cfs_end < 0 || fifo_runtime < 0)
		ksft_exit_fail_msg("cannot read /proc/<pid>/stat\n");
	if (t_start < 0 || t_end <= t_start)
		ksft_exit_fail_msg("cannot read CLOCK_MONOTONIC\n");

	share = (cfs_end - cfs_start) / (t_end - t_start);
	want = MIN_SHARE_OF_RESERVATION * runtime / period;

	ksft_print_msg("FIFO task ran %.3fs, CFS task ran %.3fs over %.3fs\n",
		       fifo_runtime, cfs_end - cfs_start, t_end - t_start);
	ksft_print_msg("CFS share of CPU%d: %.3f%%, need %.3f%%\n",
		       sib1, share * 100, want * 100);

	ksft_test_result(share >= want,
			 "CFS task gets the fair server reservation while forced idle\n");

	ksft_finished();
}
