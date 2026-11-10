// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE
#include <linux/limits.h>
#include <sys/param.h>
#include <sys/sysinfo.h>
#include <sys/wait.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include "kselftest.h"
#include "cgroup_util.h"

enum hog_clock_type {
	// Count elapsed time using the CLOCK_PROCESS_CPUTIME_ID clock.
	CPU_HOG_CLOCK_PROCESS,
	// Count elapsed time using system wallclock time.
	CPU_HOG_CLOCK_WALL,
};

struct cpu_hogger {
	char *cgroup;
	pid_t pid;
	long usage;
};

struct cpu_hog_func_param {
	int nprocs;
	struct timespec ts;
	enum hog_clock_type clock_type;
};

/*
 * This test creates two nested cgroups with and without enabling
 * the cpu controller.
 */
static int test_cpucg_subtree_control(const char *root)
{
	char *parent = NULL, *child = NULL, *parent2 = NULL, *child2 = NULL;
	int ret = KSFT_FAIL;

	// Create two nested cgroups with the cpu controller enabled.
	parent = cg_name(root, "cpucg_test_0");
	if (!parent)
		goto cleanup;

	if (cg_create(parent))
		goto cleanup;

	if (cg_write(parent, "cgroup.subtree_control", "+cpu"))
		goto cleanup;

	child = cg_name(parent, "cpucg_test_child");
	if (!child)
		goto cleanup;

	if (cg_create(child))
		goto cleanup;

	if (cg_read_strstr(child, "cgroup.controllers", "cpu"))
		goto cleanup;

	// Create two nested cgroups without enabling the cpu controller.
	parent2 = cg_name(root, "cpucg_test_1");
	if (!parent2)
		goto cleanup;

	if (cg_create(parent2))
		goto cleanup;

	child2 = cg_name(parent2, "cpucg_test_child");
	if (!child2)
		goto cleanup;

	if (cg_create(child2))
		goto cleanup;

	if (!cg_read_strstr(child2, "cgroup.controllers", "cpu"))
		goto cleanup;

	ret = KSFT_PASS;

cleanup:
	cg_destroy(child);
	free(child);
	cg_destroy(child2);
	free(child2);
	cg_destroy(parent);
	free(parent);
	cg_destroy(parent2);
	free(parent2);

	return ret;
}

static void *hog_cpu_thread_func(void *arg)
{
	while (1)
		;

	return NULL;
}

static struct timespec
timespec_sub(const struct timespec *lhs, const struct timespec *rhs)
{
	struct timespec zero = {
		.tv_sec = 0,
		.tv_nsec = 0,
	};
	struct timespec ret;

	if (lhs->tv_sec < rhs->tv_sec)
		return zero;

	ret.tv_sec = lhs->tv_sec - rhs->tv_sec;

	if (lhs->tv_nsec < rhs->tv_nsec) {
		if (ret.tv_sec == 0)
			return zero;

		ret.tv_sec--;
		ret.tv_nsec = NSEC_PER_SEC - rhs->tv_nsec + lhs->tv_nsec;
	} else
		ret.tv_nsec = lhs->tv_nsec - rhs->tv_nsec;

	return ret;
}

static int hog_cpus_timed(const char *cgroup, void *arg)
{
	const struct cpu_hog_func_param *param =
		(struct cpu_hog_func_param *)arg;
	struct timespec ts_run = param->ts;
	struct timespec ts_remaining = ts_run;
	struct timespec ts_start;
	int i, ret;

	ret = clock_gettime(CLOCK_MONOTONIC, &ts_start);
	if (ret != 0)
		return ret;

	for (i = 0; i < param->nprocs; i++) {
		pthread_t tid;

		ret = pthread_create(&tid, NULL, &hog_cpu_thread_func, NULL);
		if (ret != 0)
			return ret;
	}

	while (ts_remaining.tv_sec > 0 || ts_remaining.tv_nsec > 0) {
		struct timespec ts_total;

		ret = nanosleep(&ts_remaining, NULL);
		if (ret && errno != EINTR)
			return ret;

		if (param->clock_type == CPU_HOG_CLOCK_PROCESS) {
			ret = clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts_total);
			if (ret != 0)
				return ret;
		} else {
			struct timespec ts_current;

			ret = clock_gettime(CLOCK_MONOTONIC, &ts_current);
			if (ret != 0)
				return ret;

			ts_total = timespec_sub(&ts_current, &ts_start);
		}

		ts_remaining = timespec_sub(&ts_run, &ts_total);
	}

	return 0;
}

/*
 * Creates a cpu cgroup, burns a CPU for a few quanta, and verifies that
 * cpu.stat shows the expected output.
 */
static int test_cpucg_stats(const char *root)
{
	int ret = KSFT_FAIL;
	long usage_usec, user_usec, system_usec;
	long usage_seconds = 2;
	long expected_usage_usec = usage_seconds * USEC_PER_SEC;
	char *cpucg;

	cpucg = cg_name(root, "cpucg_test");
	if (!cpucg)
		goto cleanup;

	if (cg_create(cpucg))
		goto cleanup;

	usage_usec = cg_read_key_long(cpucg, "cpu.stat", "usage_usec");
	user_usec = cg_read_key_long(cpucg, "cpu.stat", "user_usec");
	system_usec = cg_read_key_long(cpucg, "cpu.stat", "system_usec");
	if (usage_usec != 0 || user_usec != 0 || system_usec != 0)
		goto cleanup;

	struct cpu_hog_func_param param = {
		.nprocs = 1,
		.ts = {
			.tv_sec = usage_seconds,
			.tv_nsec = 0,
		},
		.clock_type = CPU_HOG_CLOCK_PROCESS,
	};
	if (cg_run(cpucg, hog_cpus_timed, (void *)&param))
		goto cleanup;

	usage_usec = cg_read_key_long(cpucg, "cpu.stat", "usage_usec");
	user_usec = cg_read_key_long(cpucg, "cpu.stat", "user_usec");
	if (user_usec <= 0)
		goto cleanup;

	if (!values_close_report(usage_usec, expected_usage_usec, 1))
		goto cleanup;

	ret = KSFT_PASS;

cleanup:
	cg_destroy(cpucg);
	free(cpucg);

	return ret;
}

/*
 * Creates a nice process that consumes CPU and checks that the elapsed
 * usertime in the cgroup is close to the expected time.
 */
static int test_cpucg_nice(const char *root)
{
	int ret = KSFT_FAIL;
	int status;
	long user_usec, nice_usec;
	long usage_seconds = 2;
	long expected_nice_usec = usage_seconds * USEC_PER_SEC;
	char *cpucg;
	pid_t pid;

	cpucg = cg_name(root, "cpucg_test");
	if (!cpucg)
		goto cleanup;

	if (cg_create(cpucg))
		goto cleanup;

	user_usec = cg_read_key_long(cpucg, "cpu.stat", "user_usec");
	nice_usec = cg_read_key_long(cpucg, "cpu.stat", "nice_usec");
	if (nice_usec == -1)
		ret = KSFT_SKIP;
	if (user_usec != 0 || nice_usec != 0)
		goto cleanup;

	/*
	 * We fork here to create a new process that can be niced without
	 * polluting the nice value of other selftests
	 */
	pid = fork();
	if (pid < 0) {
		goto cleanup;
	} else if (pid == 0) {
		struct cpu_hog_func_param param = {
			.nprocs = 1,
			.ts = {
				.tv_sec = usage_seconds,
				.tv_nsec = 0,
			},
			.clock_type = CPU_HOG_CLOCK_PROCESS,
		};
		char buf[64];
		snprintf(buf, sizeof(buf), "%d", getpid());
		if (cg_write(cpucg, "cgroup.procs", buf))
			exit(EXIT_FAILURE);

		/* Try to keep niced CPU usage as constrained to hog_cpu as possible */
		nice(1);
		hog_cpus_timed(cpucg, &param);
		exit(0);
	} else {
		waitpid(pid, &status, 0);
		if (!WIFEXITED(status))
			goto cleanup;

		user_usec = cg_read_key_long(cpucg, "cpu.stat", "user_usec");
		nice_usec = cg_read_key_long(cpucg, "cpu.stat", "nice_usec");
		if (user_usec <= 0)
			goto cleanup;
		if (!values_close_report(nice_usec, expected_nice_usec, 1))
			goto cleanup;

		ret = KSFT_PASS;
	}

cleanup:
	cg_destroy(cpucg);
	free(cpucg);

	return ret;
}

static int
run_cpucg_weight_test(
		const char *root,
		pid_t (*spawn_child)(const struct cpu_hogger *child),
		int (*validate)(const struct cpu_hogger *children, int num_children))
{
	int ret = KSFT_FAIL, i;
	char *parent = NULL;
	struct cpu_hogger children[3] = {};

	parent = cg_name(root, "cpucg_test_0");
	if (!parent)
		goto cleanup;

	if (cg_create(parent))
		goto cleanup;

	if (cg_write(parent, "cgroup.subtree_control", "+cpu"))
		goto cleanup;

	for (i = 0; i < ARRAY_SIZE(children); i++) {
		children[i].cgroup = cg_name_indexed(parent, "cpucg_child", i);
		if (!children[i].cgroup)
			goto cleanup;

		if (cg_create(children[i].cgroup))
			goto cleanup;

		if (cg_write_numeric(children[i].cgroup, "cpu.weight",
					50 * (i + 1)))
			goto cleanup;
	}

	for (i = 0; i < ARRAY_SIZE(children); i++) {
		pid_t pid = spawn_child(&children[i]);
		if (pid <= 0)
			goto cleanup;
		children[i].pid = pid;
	}

	for (i = 0; i < ARRAY_SIZE(children); i++) {
		int retcode;

		waitpid(children[i].pid, &retcode, 0);
		if (!WIFEXITED(retcode))
			goto cleanup;
		if (WEXITSTATUS(retcode))
			goto cleanup;
	}

	for (i = 0; i < ARRAY_SIZE(children); i++)
		children[i].usage = cg_read_key_long(children[i].cgroup,
				"cpu.stat", "usage_usec");

	if (validate(children, ARRAY_SIZE(children)))
		goto cleanup;

	ret = KSFT_PASS;
cleanup:
	for (i = 0; i < ARRAY_SIZE(children); i++) {
		cg_destroy(children[i].cgroup);
		free(children[i].cgroup);
	}
	cg_destroy(parent);
	free(parent);

	return ret;
}

static pid_t weight_hog_ncpus(const struct cpu_hogger *child, int ncpus)
{
	long usage_seconds = 10;
	struct cpu_hog_func_param param = {
		.nprocs = ncpus,
		.ts = {
			.tv_sec = usage_seconds,
			.tv_nsec = 0,
		},
		.clock_type = CPU_HOG_CLOCK_WALL,
	};
	return cg_run_nowait(child->cgroup, hog_cpus_timed, (void *)&param);
}

static pid_t weight_hog_all_cpus(const struct cpu_hogger *child)
{
	return weight_hog_ncpus(child, get_nprocs());
}

static int
overprovision_validate(const struct cpu_hogger *children, int num_children)
{
	int ret = KSFT_FAIL, i;

	for (i = 0; i < num_children - 1; i++) {
		long delta;

		if (children[i + 1].usage <= children[i].usage)
			goto cleanup;

		delta = children[i + 1].usage - children[i].usage;
		if (!values_close_report(delta, children[0].usage, 35))
			goto cleanup;
	}

	ret = KSFT_PASS;
cleanup:
	return ret;
}

/*
 * First, this test creates the following hierarchy:
 * A
 * A/B     cpu.weight = 50
 * A/C     cpu.weight = 100
 * A/D     cpu.weight = 150
 *
 * A separate process is then created for each child cgroup which spawns as
 * many threads as there are cores, and hogs each CPU as much as possible
 * for some time interval.
 *
 * Once all of the children have exited, we verify that each child cgroup
 * was given proportional runtime as informed by their cpu.weight.
 */
static int test_cpucg_weight_overprovisioned(const char *root)
{
	return run_cpucg_weight_test(root, weight_hog_all_cpus,
			overprovision_validate);
}

static pid_t weight_hog_one_cpu(const struct cpu_hogger *child)
{
	return weight_hog_ncpus(child, 1);
}

static int
underprovision_validate(const struct cpu_hogger *children, int num_children)
{
	int ret = KSFT_FAIL, i;

	for (i = 0; i < num_children - 1; i++) {
		if (!values_close_report(children[i + 1].usage, children[0].usage, 15))
			goto cleanup;
	}

	ret = KSFT_PASS;
cleanup:
	return ret;
}

/*
 * First, this test creates the following hierarchy:
 * A
 * A/B     cpu.weight = 50
 * A/C     cpu.weight = 100
 * A/D     cpu.weight = 150
 *
 * A separate process is then created for each child cgroup which spawns a
 * single thread that hogs a CPU. The testcase is only run on systems that
 * have at least one core per-thread in the child processes.
 *
 * Once all of the children have exited, we verify that each child cgroup
 * had roughly the same runtime despite having different cpu.weight.
 */
static int test_cpucg_weight_underprovisioned(const char *root)
{
	// Only run the test if there are enough cores to avoid overprovisioning
	// the system.
	if (get_nprocs() < 4)
		return KSFT_SKIP;

	return run_cpucg_weight_test(root, weight_hog_one_cpu,
			underprovision_validate);
}

static int
run_cpucg_nested_weight_test(const char *root, bool overprovisioned)
{
	int ret = KSFT_FAIL, i;
	char *parent = NULL, *child = NULL;
	struct cpu_hogger leaf[3] = {};
	long nested_leaf_usage, child_usage;
	int nprocs = get_nprocs();

	if (!overprovisioned) {
		if (nprocs < 4)
			/*
			 * Only run the test if there are enough cores to avoid overprovisioning
			 * the system.
			 */
			return KSFT_SKIP;
		nprocs /= 4;
	}

	parent = cg_name(root, "cpucg_test");
	child = cg_name(parent, "cpucg_child");
	if (!parent || !child)
		goto cleanup;

	if (cg_create(parent))
		goto cleanup;
	if (cg_write(parent, "cgroup.subtree_control", "+cpu"))
		goto cleanup;

	if (cg_create(child))
		goto cleanup;
	if (cg_write(child, "cgroup.subtree_control", "+cpu"))
		goto cleanup;
	if (cg_write(child, "cpu.weight", "1000"))
		goto cleanup;

	for (i = 0; i < ARRAY_SIZE(leaf); i++) {
		const char *ancestor;
		long weight;

		if (i == 0) {
			ancestor = parent;
			weight = 1000;
		} else {
			ancestor = child;
			weight = 5000;
		}
		leaf[i].cgroup = cg_name_indexed(ancestor, "cpucg_leaf", i);
		if (!leaf[i].cgroup)
			goto cleanup;

		if (cg_create(leaf[i].cgroup))
			goto cleanup;

		if (cg_write_numeric(leaf[i].cgroup, "cpu.weight", weight))
			goto cleanup;
	}

	for (i = 0; i < ARRAY_SIZE(leaf); i++) {
		pid_t pid;
		struct cpu_hog_func_param param = {
			.nprocs = nprocs,
			.ts = {
				.tv_sec = 10,
				.tv_nsec = 0,
			},
			.clock_type = CPU_HOG_CLOCK_WALL,
		};

		pid = cg_run_nowait(leaf[i].cgroup, hog_cpus_timed,
				(void *)&param);
		if (pid <= 0)
			goto cleanup;
		leaf[i].pid = pid;
	}

	for (i = 0; i < ARRAY_SIZE(leaf); i++) {
		int retcode;

		waitpid(leaf[i].pid, &retcode, 0);
		if (!WIFEXITED(retcode))
			goto cleanup;
		if (WEXITSTATUS(retcode))
			goto cleanup;
	}

	for (i = 0; i < ARRAY_SIZE(leaf); i++) {
		leaf[i].usage = cg_read_key_long(leaf[i].cgroup,
				"cpu.stat", "usage_usec");
		if (leaf[i].usage <= 0)
			goto cleanup;
	}

	nested_leaf_usage = leaf[1].usage + leaf[2].usage;
	if (overprovisioned) {
		if (!values_close_report(leaf[0].usage, nested_leaf_usage, 15))
			goto cleanup;
	} else if (!values_close_report(leaf[0].usage * 2, nested_leaf_usage, 15))
		goto cleanup;


	child_usage = cg_read_key_long(child, "cpu.stat", "usage_usec");
	if (child_usage <= 0)
		goto cleanup;
	if (!values_close_report(child_usage, nested_leaf_usage, 1))
		goto cleanup;

	ret = KSFT_PASS;
cleanup:
	for (i = 0; i < ARRAY_SIZE(leaf); i++) {
		cg_destroy(leaf[i].cgroup);
		free(leaf[i].cgroup);
	}
	cg_destroy(child);
	free(child);
	cg_destroy(parent);
	free(parent);

	return ret;
}

/*
 * First, this test creates the following hierarchy:
 * A
 * A/B     cpu.weight = 1000
 * A/C     cpu.weight = 1000
 * A/C/D   cpu.weight = 5000
 * A/C/E   cpu.weight = 5000
 *
 * A separate process is then created for each leaf, which spawn nproc threads
 * that burn a CPU for a few seconds.
 *
 * Once all of those processes have exited, we verify that each of the leaf
 * cgroups have roughly the same usage from cpu.stat.
 */
static int
test_cpucg_nested_weight_overprovisioned(const char *root)
{
	return run_cpucg_nested_weight_test(root, true);
}

/*
 * First, this test creates the following hierarchy:
 * A
 * A/B     cpu.weight = 1000
 * A/C     cpu.weight = 1000
 * A/C/D   cpu.weight = 5000
 * A/C/E   cpu.weight = 5000
 *
 * A separate process is then created for each leaf, which nproc / 4 threads
 * that burns a CPU for a few seconds.
 *
 * Once all of those processes have exited, we verify that each of the leaf
 * cgroups have roughly the same usage from cpu.stat.
 */
static int
test_cpucg_nested_weight_underprovisioned(const char *root)
{
	return run_cpucg_nested_weight_test(root, false);
}

/*
 * Best effort attempt to get the kernel's HZ value from the config.
 * Return the HZ value if found otherwise return 1000 (the default) to
 * indicate failure.
 */
static long
get_config_hz(void)
{
	long hz = 1000;
	FILE *f;
	char cmd[256] = "zcat /proc/config.gz 2>/dev/null | grep '^CONFIG_HZ='";

	f = popen(cmd, "r");

	if (!f)
		return hz;

	if (fscanf(f, "CONFIG_HZ=%ld", &hz) == EOF)
		goto out;

out:
	pclose(f);
	return hz;
}

/*
 * This test creates a cgroup with some maximum value within a period, and
 * verifies that a process in the cgroup is not overscheduled.
 */
static int test_cpucg_max(const char *root)
{
	int ret = KSFT_FAIL;
	long hz = get_config_hz();
	long quota_usec = 1000;
	long default_period_usec = 100000; /* cpu.max's default period */
	long duration_seconds = 1;

	long duration_usec;
	long usage_usec, n_periods, remainder_usec, expected_usage_usec;
	char *cpucg;
	char quota_buf[32];

	duration_usec = duration_seconds * USEC_PER_SEC * 1000 / hz;

	snprintf(quota_buf, sizeof(quota_buf), "%ld", quota_usec);

	cpucg = cg_name(root, "cpucg_test");
	if (!cpucg)
		goto cleanup;

	if (cg_create(cpucg))
		goto cleanup;

	if (cg_write(cpucg, "cpu.max", quota_buf))
		goto cleanup;

	struct cpu_hog_func_param param = {
		.nprocs = 1,
		.ts = {
			.tv_sec = duration_usec / USEC_PER_SEC,
			.tv_nsec = duration_usec % USEC_PER_SEC * NSEC_PER_USEC,
		},
		.clock_type = CPU_HOG_CLOCK_WALL,
	};
	if (cg_run(cpucg, hog_cpus_timed, (void *)&param))
		goto cleanup;

	usage_usec = cg_read_key_long(cpucg, "cpu.stat", "usage_usec");
	if (usage_usec <= 0)
		goto cleanup;

	/*
	 * The following calculation applies only since
	 * the cpu hog is set to run as per wall-clock time
	 */
	n_periods = duration_usec / default_period_usec;
	remainder_usec = duration_usec - n_periods * default_period_usec;
	expected_usage_usec
		= n_periods * quota_usec + MIN(remainder_usec, quota_usec);

	if (!values_close_report(usage_usec, expected_usage_usec, 10))
		goto cleanup;

	ret = KSFT_PASS;

cleanup:
	cg_destroy(cpucg);
	free(cpucg);

	return ret;
}

/*
 * This test verifies that a process inside of a nested cgroup whose parent
 * group has a cpu.max value set, is properly throttled.
 */
static int test_cpucg_max_nested(const char *root)
{
	int ret = KSFT_FAIL;
	long hz = get_config_hz();
	long quota_usec = 1000;
	long default_period_usec = 100000; /* cpu.max's default period */
	long duration_seconds = 1;

	long duration_usec;
	long usage_usec, n_periods, remainder_usec, expected_usage_usec;
	char *parent, *child;
	char quota_buf[32];

	duration_usec = duration_seconds * USEC_PER_SEC * 1000 / hz;

	snprintf(quota_buf, sizeof(quota_buf), "%ld", quota_usec);

	parent = cg_name(root, "cpucg_parent");
	child = cg_name(parent, "cpucg_child");
	if (!parent || !child)
		goto cleanup;

	if (cg_create(parent))
		goto cleanup;

	if (cg_write(parent, "cgroup.subtree_control", "+cpu"))
		goto cleanup;

	if (cg_create(child))
		goto cleanup;

	if (cg_write(parent, "cpu.max", quota_buf))
		goto cleanup;

	struct cpu_hog_func_param param = {
		.nprocs = 1,
		.ts = {
			.tv_sec = duration_usec / USEC_PER_SEC,
			.tv_nsec = duration_usec % USEC_PER_SEC * NSEC_PER_USEC,
		},
		.clock_type = CPU_HOG_CLOCK_WALL,
	};
	if (cg_run(child, hog_cpus_timed, (void *)&param))
		goto cleanup;

	usage_usec = cg_read_key_long(child, "cpu.stat", "usage_usec");
	if (usage_usec <= 0)
		goto cleanup;

	/*
	 * The following calculation applies only since
	 * the cpu hog is set to run as per wall-clock time
	 */
	n_periods = duration_usec / default_period_usec;
	remainder_usec = duration_usec - n_periods * default_period_usec;
	expected_usage_usec
		= n_periods * quota_usec + MIN(remainder_usec, quota_usec);

	if (!values_close_report(usage_usec, expected_usage_usec, 10))
		goto cleanup;

	ret = KSFT_PASS;

cleanup:
	cg_destroy(child);
	free(child);
	cg_destroy(parent);
	free(parent);

	return ret;
}

/* Wait until the period timer of @cgroup starts a new period. */
static int wait_period_start(const char *cgroup)
{
	long nr_periods = cg_read_key_long(cgroup, "cpu.stat", "nr_periods");
	int i;

	for (i = 0; i < 3000; i++) {
		usleep(1000);
		if (cg_read_key_long(cgroup, "cpu.stat", "nr_periods") != nr_periods)
			return 0;
	}
	return -1;
}

static long long monotonic_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

/* For (long)arg seconds, run for 1ms and then sleep for 10ms. */
static int run_and_sleep(const char *cgroup, void *arg)
{
	long long end = monotonic_ns() + (long)arg * 1000000000LL;
	long long start;

	while ((start = monotonic_ns()) < end) {
		while (monotonic_ns() - start < 1000000)
			;
		usleep(10000);
	}
	return 0;
}

static int test_cpucg_max_runtime(const char *root)
{
	int ret = KSFT_FAIL;
	long quota_usec = 1000;		/* 1ms (minimum) */
	long period_usec = 100000;	/* 100ms */
	long burst_usec = 5000000;	/* 5s, so cap = 5001ms */
	long runtime_usec = 2500000;	/* 2500ms, half of the 5s run */
	long duration_sec = 5;
	/* The injected runtime plus the quota refilled each period of the run */
	long expected_usec = runtime_usec +
			     duration_sec * USEC_PER_SEC / period_usec * quota_usec;
	long usage_usec;
	char *cpucg;
	char buf[64];
	int pid;

	cpucg = cg_name(root, "cpucg_runtime_test");
	if (!cpucg)
		goto cleanup;

	if (cg_create(cpucg))
		goto cleanup;

	/* Without a quota there is no runtime to set. */
	if (!cg_write_numeric(cpucg, "cpu.max.runtime", runtime_usec))
		goto cleanup;

	snprintf(buf, sizeof(buf), "%ld %ld", quota_usec, period_usec);
	if (cg_write(cpucg, "cpu.max", buf))
		goto cleanup;
	if (cg_write_numeric(cpucg, "cpu.max.burst", burst_usec))
		goto cleanup;

	/* Start burner, let it settle, then inject credits */
	struct cpu_hog_func_param param = {
		.nprocs = 1,
		.ts = { .tv_sec = duration_sec, .tv_nsec = 0 },
		.clock_type = CPU_HOG_CLOCK_WALL,
	};
	pid = cg_run_nowait(cpucg, hog_cpus_timed, (void *)&param);
	if (pid < 0)
		goto cleanup;

	usleep(100000);
	if (cg_write_numeric(cpucg, "cpu.max.runtime", runtime_usec)) {
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		goto cleanup;
	}

	waitpid(pid, NULL, 0);

	usage_usec = cg_read_key_long(cpucg, "cpu.stat", "usage_usec");
	if (usage_usec <= 0)
		goto cleanup;

	/* At least the injected runtime, at most 5% above the expected usage. */
	if (usage_usec < runtime_usec ||
	    usage_usec > expected_usec + expected_usec / 20)
		goto cleanup;

	ret = KSFT_PASS;

cleanup:
	cg_destroy(cpucg);
	free(cpucg);
	return ret;
}

/*
 * A cpu.max.runtime write is not burst usage: writing a runtime below the
 * current one leaves cpu.stat's nr_bursts and burst_usec where they were.
 */
static int test_cpucg_max_runtime_burst_stats(const char *root)
{
	int ret = KSFT_FAIL;
	long nr_bursts, burst_usec;
	char *cpucg;

	cpucg = cg_name(root, "cpucg_runtime_burst_stats_test");
	if (!cpucg)
		goto cleanup;

	if (cg_create(cpucg))
		goto cleanup;

	/* A long period, so the write lands before the timer's first refill. */
	if (cg_write(cpucg, "cpu.max", "10000 1000000"))
		goto cleanup;
	if (cg_write_numeric(cpucg, "cpu.max.burst", 190000))
		goto cleanup;
	if (cg_write_numeric(cpucg, "cpu.max.runtime", 0))
		goto cleanup;

	/* The idle group refills for a few periods. */
	sleep(3);
	nr_bursts = cg_read_key_long(cpucg, "cpu.stat", "nr_bursts");
	burst_usec = cg_read_key_long(cpucg, "cpu.stat", "burst_usec");
	if (nr_bursts != 0 || burst_usec != 0)
		goto cleanup;

	ret = KSFT_PASS;

cleanup:
	cg_destroy(cpucg);
	free(cpucg);
	return ret;
}

/*
 * A cpu.max.runtime write hands the runtime to a throttled group at once,
 * rather than at the next period: with a 1s period, the group runs again
 * within 100ms of the write, before the next period starts.
 */
static int test_cpucg_max_runtime_unthrottle(const char *root)
{
	int ret = KSFT_FAIL;
	long usage_before, usage_after, nr_periods;
	char *cpucg;
	int pid;

	cpucg = cg_name(root, "cpucg_runtime_unthrottle_test");
	if (!cpucg)
		goto cleanup;

	if (cg_create(cpucg))
		goto cleanup;

	/* 1ms per 1s period, with room for a runtime of up to 1s. */
	if (cg_write(cpucg, "cpu.max", "1000 1000000"))
		goto cleanup;
	if (cg_write_numeric(cpucg, "cpu.max.burst", 999000))
		goto cleanup;

	struct cpu_hog_func_param param = {
		.nprocs = 1,
		.ts = { .tv_sec = 2, .tv_nsec = 0 },
		.clock_type = CPU_HOG_CLOCK_WALL,
	};
	pid = cg_run_nowait(cpucg, hog_cpus_timed, (void *)&param);
	if (pid < 0)
		goto cleanup;

	/*
	 * The period timer's phase is random: start right after a boundary,
	 * so that the next one is some 900ms away. The hog uses up its runtime
	 * and is throttled for the period.
	 */
	if (wait_period_start(cpucg))
		goto cleanup_hog;
	nr_periods = cg_read_key_long(cpucg, "cpu.stat", "nr_periods");
	usleep(50000);
	usage_before = cg_read_key_long(cpucg, "cpu.stat", "usage_usec");
	if (usage_before < 0 || usage_before > 20000)
		goto cleanup_hog;

	if (cg_write_numeric(cpucg, "cpu.max.runtime", 500000))
		goto cleanup_hog;

	/* No period started meanwhile: only the write lets the hog run. */
	usleep(100000);
	usage_after = cg_read_key_long(cpucg, "cpu.stat", "usage_usec");
	if (cg_read_key_long(cpucg, "cpu.stat", "nr_periods") != nr_periods)
		goto cleanup_hog;
	if (usage_after - usage_before < 50000)
		goto cleanup_hog;

	ret = KSFT_PASS;

cleanup_hog:
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
cleanup:
	cg_destroy(cpucg);
	free(cpucg);
	return ret;
}

/*
 * What a group ran beyond its quota before a cpu.max.runtime write is still
 * burst usage: a write of the runtime the group has left does not hide it.
 */
static int test_cpucg_max_runtime_burst_kept(const char *root)
{
	int ret = KSFT_FAIL;
	long burst_before, burst_after, runtime_usec;
	char *cpucg;
	int pid;

	cpucg = cg_name(root, "cpucg_runtime_burst_kept_test");
	if (!cpucg)
		goto cleanup;

	if (cg_create(cpucg))
		goto cleanup;

	/* 10ms per 1s period, and a runtime of 1s to run on. */
	if (cg_write(cpucg, "cpu.max", "10000 1000000"))
		goto cleanup;
	if (cg_write_numeric(cpucg, "cpu.max.burst", 990000))
		goto cleanup;
	if (cg_write_numeric(cpucg, "cpu.max.runtime", 1000000))
		goto cleanup;

	struct cpu_hog_func_param param = {
		.nprocs = 1,
		.ts = { .tv_sec = 10, .tv_nsec = 0 },
		.clock_type = CPU_HOG_CLOCK_WALL,
	};
	pid = cg_run_nowait(cpucg, hog_cpus_timed, (void *)&param);
	if (pid < 0)
		goto cleanup;

	/* Run some 300ms, all in one period, and stop. */
	if (wait_period_start(cpucg)) {
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		goto cleanup;
	}
	burst_before = cg_read_key_long(cpucg, "cpu.stat", "burst_usec");
	usleep(300000);
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);

	/* Write back what is left: the next refill counts the 300ms run. */
	runtime_usec = cg_read_long(cpucg, "cpu.max.runtime");
	if (cg_write_numeric(cpucg, "cpu.max.runtime", runtime_usec))
		goto cleanup;
	sleep(1);
	burst_after = cg_read_key_long(cpucg, "cpu.stat", "burst_usec");
	if (burst_before < 0 || burst_after - burst_before < 250000)
		goto cleanup;

	ret = KSFT_PASS;

cleanup:
	cg_destroy(cpucg);
	free(cpucg);
	return ret;
}

/*
 * cpu.max.runtime reads at most quota + burst, so that a value read can be
 * written back. A cfs_rq that dequeues returns its unused runtime, which can
 * take the runtime above quota + burst until the next refill caps it: run
 * tasks that keep doing that, and read and write back the runtime meanwhile.
 */
static int test_cpucg_max_runtime_read_capped(const char *root)
{
	int ret = KSFT_FAIL;
	long cap_usec = 100000;		/* quota 100ms, no burst */
	long long end;
	long runtime_usec;
	char *cpucg;
	int pids[2];
	int i, n = 0;

	cpucg = cg_name(root, "cpucg_runtime_read_capped_test");
	if (!cpucg)
		goto cleanup;

	if (cg_create(cpucg))
		goto cleanup;

	if (cg_write(cpucg, "cpu.max", "100000 100000"))
		goto cleanup;

	for (n = 0; n < 2; n++) {
		pids[n] = cg_run_nowait(cpucg, run_and_sleep, (void *)4L);
		if (pids[n] < 0)
			goto cleanup_tasks;
	}

	end = monotonic_ns() + 3000000000LL;
	while (monotonic_ns() < end) {
		runtime_usec = cg_read_long(cpucg, "cpu.max.runtime");
		if (runtime_usec < 0 || runtime_usec > cap_usec)
			goto cleanup_tasks;
		if (cg_write_numeric(cpucg, "cpu.max.runtime", runtime_usec))
			goto cleanup_tasks;
	}

	ret = KSFT_PASS;

cleanup_tasks:
	for (i = 0; i < n; i++) {
		kill(pids[i], SIGKILL);
		waitpid(pids[i], NULL, 0);
	}
cleanup:
	cg_destroy(cpucg);
	free(cpucg);
	return ret;
}

/*
 * A group with a burst keeps earning quota while it is idle, up to
 * quota + burst, and cpu.max.runtime reads what it has earned. Without a
 * burst the runtime stays at quota.
 */
static int test_cpucg_max_idle_refill(const char *root)
{
	int ret = KSFT_FAIL;
	long quota_usec = 10000;	/* 10ms */
	long period_usec = 100000;	/* 100ms */
	long burst_usec = 990000;	/* cap 1s */
	long runtime_usec;
	char *cpucg;
	char buf[64];

	cpucg = cg_name(root, "cpucg_idle_refill_test");
	if (!cpucg)
		goto cleanup;

	if (cg_create(cpucg))
		goto cleanup;

	snprintf(buf, sizeof(buf), "%ld %ld", quota_usec, period_usec);
	if (cg_write(cpucg, "cpu.max", buf))
		goto cleanup;

	/* No burst: the runtime stays at quota while idle. */
	sleep(1);
	runtime_usec = cg_read_long(cpucg, "cpu.max.runtime");
	if (runtime_usec != quota_usec)
		goto cleanup;

	/* Burst: the write refills once (20ms), then 1s idle earns 10 more. */
	if (cg_write_numeric(cpucg, "cpu.max.burst", burst_usec))
		goto cleanup;
	sleep(1);
	runtime_usec = cg_read_long(cpucg, "cpu.max.runtime");
	if (runtime_usec < 110000 || runtime_usec > 130000)
		goto cleanup;

	/* Capped at quota + burst. */
	sleep(10);
	runtime_usec = cg_read_long(cpucg, "cpu.max.runtime");
	if (runtime_usec != quota_usec + burst_usec)
		goto cleanup;

	/*
	 * A write sets the runtime from now on: 500ms later, five refills, or
	 * six if the sleep overruns into the next period.
	 */
	if (cg_write_numeric(cpucg, "cpu.max.runtime", 0))
		goto cleanup;
	usleep(500000);
	runtime_usec = cg_read_long(cpucg, "cpu.max.runtime");
	if (runtime_usec < 50000 || runtime_usec > 60000)
		goto cleanup;

	ret = KSFT_PASS;

cleanup:
	cg_destroy(cpucg);
	free(cpucg);
	return ret;
}

/*
 * A cpu.max or cpu.max.burst write applies from then on: what a group with
 * a quota earned while idle is kept, capped at the new quota + burst, and a
 * group that had no quota has earned nothing while it had none.
 */
static int test_cpucg_max_idle_refill_write(const char *root)
{
	int ret = KSFT_FAIL;
	long quota_usec = 10000;	/* 10ms */
	long period_usec = 100000;	/* 100ms */
	long runtime_usec;
	char *cpucg = NULL, *fresh = NULL;
	char buf[64];

	cpucg = cg_name(root, "cpucg_idle_refill_write_test");
	fresh = cg_name(root, "cpucg_idle_refill_fresh_test");
	if (!cpucg || !fresh)
		goto cleanup;

	if (cg_create(cpucg) || cg_create(fresh))
		goto cleanup;

	snprintf(buf, sizeof(buf), "%ld %ld", quota_usec, period_usec);
	if (cg_write(cpucg, "cpu.max", buf))
		goto cleanup;
	if (cg_write_numeric(cpucg, "cpu.max.burst", 190000))
		goto cleanup;

	/* 3s idle fills the group to quota + burst. */
	sleep(3);
	runtime_usec = cg_read_long(cpucg, "cpu.max.runtime");
	if (runtime_usec != 200000)
		goto cleanup;

	/* Writing the same cpu.max keeps what the group earned. */
	if (cg_write(cpucg, "cpu.max", buf))
		goto cleanup;
	runtime_usec = cg_read_long(cpucg, "cpu.max.runtime");
	if (runtime_usec != 200000)
		goto cleanup;

	/* A lower burst keeps it too, capped at the new quota + burst. */
	sleep(2);
	if (cg_write_numeric(cpucg, "cpu.max.burst", 90000))
		goto cleanup;
	runtime_usec = cg_read_long(cpucg, "cpu.max.runtime");
	if (runtime_usec != 100000)
		goto cleanup;

	/* A group given a quota after idling without one starts with a refill. */
	if (cg_write_numeric(fresh, "cpu.max.burst", 190000))
		goto cleanup;
	sleep(2);
	if (cg_write(fresh, "cpu.max", buf))
		goto cleanup;
	runtime_usec = cg_read_long(fresh, "cpu.max.runtime");
	if (runtime_usec != quota_usec)
		goto cleanup;

	ret = KSFT_PASS;

cleanup:
	if (fresh)
		cg_destroy(fresh);
	if (cpucg)
		cg_destroy(cpucg);
	free(fresh);
	free(cpucg);
	return ret;
}

/*
 * A cpu.max.runtime write sets the runtime exactly, and only the periods
 * after it refill.
 */
static int test_cpucg_max_idle_refill_runtime_write(const char *root)
{
	int ret = KSFT_FAIL;
	long runtime_usec;
	char *cpucg;

	cpucg = cg_name(root, "cpucg_idle_refill_runtime_test");
	if (!cpucg)
		goto cleanup;

	if (cg_create(cpucg))
		goto cleanup;

	if (cg_write(cpucg, "cpu.max", "10000 100000"))
		goto cleanup;
	if (cg_write_numeric(cpucg, "cpu.max.burst", 190000))
		goto cleanup;

	sleep(3);
	if (cg_write_numeric(cpucg, "cpu.max.runtime", 30000))
		goto cleanup;
	/* One refill if a period boundary passes before the read. */
	runtime_usec = cg_read_long(cpucg, "cpu.max.runtime");
	if (runtime_usec != 30000 && runtime_usec != 40000)
		goto cleanup;

	/* 250ms after the write: two or three refills, by the boundaries. */
	usleep(250000);
	runtime_usec = cg_read_long(cpucg, "cpu.max.runtime");
	if (runtime_usec < 50000 || runtime_usec > 60000)
		goto cleanup;

	ret = KSFT_PASS;

cleanup:
	cg_destroy(cpucg);
	free(cpucg);
	return ret;
}

#define T(x) { x, #x }
struct cpucg_test {
	int (*fn)(const char *root);
	const char *name;
} tests[] = {
	T(test_cpucg_subtree_control),
	T(test_cpucg_stats),
	T(test_cpucg_nice),
	T(test_cpucg_weight_overprovisioned),
	T(test_cpucg_weight_underprovisioned),
	T(test_cpucg_nested_weight_overprovisioned),
	T(test_cpucg_nested_weight_underprovisioned),
	T(test_cpucg_max),
	T(test_cpucg_max_nested),
	T(test_cpucg_max_runtime),
	T(test_cpucg_max_runtime_burst_stats),
	T(test_cpucg_max_runtime_unthrottle),
	T(test_cpucg_max_runtime_burst_kept),
	T(test_cpucg_max_runtime_read_capped),
	T(test_cpucg_max_idle_refill),
	T(test_cpucg_max_idle_refill_write),
	T(test_cpucg_max_idle_refill_runtime_write),
};
#undef T

int main(int argc, char *argv[])
{
	char root[PATH_MAX];
	int i;

	ksft_print_header();
	if (cg_find_unified_root(root, sizeof(root), NULL))
		ksft_exit_skip("cgroup v2 isn't mounted\n");

	if (cg_write(root, "cgroup.subtree_control", "+cpu"))
		ksft_exit_skip("Failed to set cpu controller\n");

	ksft_set_plan(ARRAY_SIZE(tests));
	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		switch (tests[i].fn(root)) {
		case KSFT_PASS:
			ksft_test_result_pass("%s\n", tests[i].name);
			break;
		case KSFT_SKIP:
			ksft_test_result_skip("%s\n", tests[i].name);
			break;
		default:
			ksft_test_result_fail("%s\n", tests[i].name);
			break;
		}
	}

	ksft_finished();
}
