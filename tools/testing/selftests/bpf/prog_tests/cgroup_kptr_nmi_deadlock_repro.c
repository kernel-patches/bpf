// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/compiler.h>
#include <linux/perf_event.h>
#include <sched.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <cgroup_helpers.h>
#include <test_progs.h>

#include "cgroup_kptr_nmi_deadlock_repro.skel.h"

#define DELETE_TIMEOUT_NS (5ULL * 1000 * 1000 * 1000)
#define REPRO_ROUNDS 256
#define REPRO_CGROUP_REL_PATH "/my_new_group"

/*
 * The reproducer relies on a PMU cycle counter to raise NMIs and on the
 * x86-only nmi_handler tracepoint, so it only runs on x86.
 */
#if defined(__x86_64__) || defined(__i386__)

static int open_kmsg_at_end(void)
{
	int fd, err;

	fd = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
	if (fd < 0)
		return -errno;
	if (lseek(fd, 0, SEEK_END) == (off_t)-1) {
		err = errno;
		close(fd);
		return -err;
	}
	return fd;
}

static bool kmsg_saw_splat(int fd)
{
	char buf[8192];
	ssize_t n;

	/* bpf_cgroup_release_dtor in any splat stack means NMI ran the dtor. */
	for (;;) {
		n = read(fd, buf, sizeof(buf) - 1);
		if (n > 0) {
			buf[n] = '\0';
			if (strstr(buf, "bpf_cgroup_release_dtor"))
				return true;
			continue;
		}
		if (n < 0 && errno == EPIPE)
			continue;
		return false;
	}
}

static int open_nmi_pmu_event_on_cpu(int cpu)
{
	struct perf_event_attr attr = {
		.freq = 1,
		.sample_freq = 1000,
		.type = PERF_TYPE_HARDWARE,
		.config = PERF_COUNT_HW_CPU_CYCLES,
	};
	int pmu_fd, err;

	pmu_fd = syscall(__NR_perf_event_open, &attr, -1, cpu, -1, 0);
	if (pmu_fd < 0) {
		err = errno;
		if (err == ENOENT || err == EOPNOTSUPP) {
			printf("%s:SKIP:no PERF_COUNT_HW_CPU_CYCLES\n", __func__);
			test__skip();
			return -1;
		}
		PRINT_FAIL("perf_event_open(cpu=%d): %s\n", cpu, strerror(err));
		return -1;
	}

	return pmu_fd;
}

static int pick_repro_cpu(void)
{
	cpu_set_t mask;
	int i;

	if (!ASSERT_OK(sched_getaffinity(getpid(), sizeof(mask), &mask),
		       "sched_getaffinity"))
		return -1;

	for (i = CPU_SETSIZE - 1; i >= 0; i--) {
		if (CPU_ISSET(i, &mask))
			return i;
	}
	return -1;
}

static bool pin_to_cpu(int cpu, cpu_set_t *old_cpuset)
{
	cpu_set_t cpuset;

	if (!ASSERT_OK(sched_getaffinity(getpid(), sizeof(*old_cpuset), old_cpuset),
		       "sched_getaffinity"))
		return false;

	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);
	return ASSERT_OK(sched_setaffinity(getpid(), sizeof(cpuset), &cpuset),
			 "sched_setaffinity");
}

static void burn_cpu(void)
{
	int i;

	/* Keep the CPU busy so PERF_COUNT_HW_CPU_CYCLES keeps raising NMIs. */
	for (i = 0; i < 1000000; i++)
		barrier();
}

static bool wait_for_cgroup_nmi_delete_batch(struct cgroup_kptr_nmi_deadlock_repro *skel,
					     int expected_deleted)
{
	u64 timeout_ns = get_time_ns() + DELETE_TIMEOUT_NS;
	int spin = 0;

	while (skel->bss->cgroup_kptr_nmi_deleted < expected_deleted) {
		burn_cpu();
		if (++spin >= 8) {
			sched_yield();
			spin = 0;
		}
		if (get_time_ns() >= timeout_ns)
			break;
	}

	return ASSERT_EQ(skel->bss->cgroup_kptr_nmi_deleted, expected_deleted,
			 "cgroup_kptr_nmi_deleted");
}

static bool wait_for_cgroup_css_free_batch(struct cgroup_kptr_nmi_deadlock_repro *skel,
					   int expected_done)
{
	struct timespec ts = { .tv_nsec = 1000 * 1000 };
	u64 timeout_ns = get_time_ns() + DELETE_TIMEOUT_NS;

	while (skel->bss->cgroup_kptr_nmi_killed_work_done < expected_done) {
		nanosleep(&ts, NULL);
		if (get_time_ns() >= timeout_ns)
			break;
	}

	return ASSERT_GE(skel->bss->cgroup_kptr_nmi_killed_work_done,
			 expected_done, "cgroup_kptr_nmi_killed_work_done");
}

static void run_cgroup_kptr_nmi_deadlock_repro(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct cgroup_kptr_nmi_deadlock_repro *skel = NULL;
	cpu_set_t old_cpuset;
	bool pinned = false;
	int pmu_fd = -1;
	int kmsg_fd = -1;
	int repro_cpu;
	int round;

	if (!ASSERT_OK(setup_cgroup_environment(), "setup_cgroup_environment"))
		return;

	skel = cgroup_kptr_nmi_deadlock_repro__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		goto cleanup_cgroup_env;

	repro_cpu = pick_repro_cpu();
	if (!ASSERT_GE(repro_cpu, 0, "pick_repro_cpu"))
		goto destroy_skel;

	pinned = pin_to_cpu(repro_cpu, &old_cpuset);
	if (!pinned)
		goto destroy_skel;

	skel->links.clear_cgroup_kptrs_from_nmi =
		bpf_program__attach_trace(skel->progs.clear_cgroup_kptrs_from_nmi);
	if (!ASSERT_OK_PTR(skel->links.clear_cgroup_kptrs_from_nmi, "attach_tp_btf"))
		goto destroy_skel;

	skel->links.mark_cgroup_killed_work_done =
		bpf_program__attach_trace(skel->progs.mark_cgroup_killed_work_done);
	if (!ASSERT_OK_PTR(skel->links.mark_cgroup_killed_work_done, "attach_fexit"))
		goto destroy_skel;

	pmu_fd = open_nmi_pmu_event_on_cpu(repro_cpu);
	if (pmu_fd < 0)
		goto destroy_skel;

	kmsg_fd = open_kmsg_at_end();
	if (!ASSERT_GE(kmsg_fd, 0, "open_kmsg_at_end"))
		goto destroy_skel;

	for (round = 0; round < REPRO_ROUNDS; round++) {
		int expected_inserted = round + 1;
		int expected_css_free;
		int cg_fd;
		int err;

		cg_fd = create_and_get_cgroup(REPRO_CGROUP_REL_PATH);
		if (!ASSERT_GE(cg_fd, 0, "create_and_get_cgroup"))
			goto destroy_skel;
		close(cg_fd);

		skel->bss->cgroup_kptr_nmi_id = get_cgroup_id(REPRO_CGROUP_REL_PATH);
		if (!ASSERT_NEQ(skel->bss->cgroup_kptr_nmi_id, 0, "get_cgroup_id"))
			goto destroy_skel;

		err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.insert_cgroup_kptr),
					     &opts);
		if (!ASSERT_OK(err, "insert_cgroup_kptr"))
			goto destroy_skel;
		if (!ASSERT_EQ(opts.retval, 0, "insert_retval"))
			goto destroy_skel;
		if (!ASSERT_EQ(skel->bss->cgroup_kptr_nmi_err, 0, "cgroup_kptr_nmi_err"))
			goto destroy_skel;
		if (!ASSERT_EQ(skel->bss->cgroup_kptr_nmi_inserted, expected_inserted,
			       "cgroup_kptr_nmi_inserted"))
			goto destroy_skel;

		expected_css_free = skel->bss->cgroup_kptr_nmi_clear_runs;

		remove_cgroup(REPRO_CGROUP_REL_PATH);

		if (!wait_for_cgroup_css_free_batch(skel, expected_css_free))
			goto destroy_skel;

		skel->bss->cgroup_kptr_nmi_nr_cgrps = expected_inserted;
		if (!wait_for_cgroup_nmi_delete_batch(skel, expected_inserted))
			goto destroy_skel;
	}

	ASSERT_FALSE(kmsg_saw_splat(kmsg_fd), "nmi_dtor_splat");

destroy_skel:
	if (pinned)
		sched_setaffinity(getpid(), sizeof(old_cpuset), &old_cpuset);
	if (kmsg_fd >= 0)
		close(kmsg_fd);
	if (pmu_fd >= 0)
		close(pmu_fd);
	cgroup_kptr_nmi_deadlock_repro__destroy(skel);
cleanup_cgroup_env:
	cleanup_cgroup_environment();
}

#endif

void test_cgroup_kptr_nmi_deadlock_repro(void)
{
#if defined(__x86_64__) || defined(__i386__)
	run_cgroup_kptr_nmi_deadlock_repro();
#else
	test__skip();
#endif
}
