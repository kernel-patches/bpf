// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/compiler.h>
#include <linux/limits.h>
#include <linux/perf_event.h>
#include <sched.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cgroup_helpers.h>
#include <test_progs.h>

#include "cgroup_kptr_nmi_deadlock_repro.skel.h"

#define DELETE_TIMEOUT_NS (5ULL * 1000 * 1000 * 1000)
#define REPRO_ROUNDS 256
#define REPRO_CPU 1
#define REPRO_CGROUP_REL_PATH "/my_new_group"
#define REPRO_CGROUP_MOUNT_PATH "/mnt"
#define REPRO_CGROUP_WORK_DIR "/cgroup-test-work-dir"

/*
 * The reproducer relies on a PMU cycle counter to raise NMIs and on the
 * x86-only nmi_handler tracepoint, so it only runs on x86.
 */
#if defined(__x86_64__) || defined(__i386__)

static void close_fd(int fd)
{
	if (fd >= 0)
		close(fd);
}

static int open_kmsg_at_end(void)
{
	int fd, saved_errno;

	fd = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
	if (fd < 0)
		return -errno;
	if (lseek(fd, 0, SEEK_END) == (off_t)-1) {
		saved_errno = errno;
		close(fd);
		return -saved_errno;
	}
	return fd;
}

static bool kmsg_saw_splat(int fd)
{
	char buf[8192];
	ssize_t n;
	bool saw = false;

	/* bpf_cgroup_release_dtor in any splat stack means NMI ran the dtor. */
	while ((n = read(fd, buf, sizeof(buf) - 1)) > 0) {
		buf[n] = '\0';
		if (strstr(buf, "bpf_cgroup_release_dtor"))
			saw = true;
	}
	return saw;
}

static void format_repro_cgroup_path(char *path, size_t path_sz,
				     const char *relative_path)
{
	snprintf(path, path_sz, "%s%s%d%s", REPRO_CGROUP_MOUNT_PATH,
		 REPRO_CGROUP_WORK_DIR, getpid(), relative_path);
}

static int create_repro_cgroup(char *cgroup_path, size_t cgroup_path_sz)
{
	format_repro_cgroup_path(cgroup_path, cgroup_path_sz,
				 REPRO_CGROUP_REL_PATH);
	if (mkdir(cgroup_path, 0777))
		return -errno;

	return 0;
}

static int remove_repro_cgroup(const char *cgroup_path)
{
	if (rmdir(cgroup_path))
		return -errno;

	return 0;
}

static int open_nmi_pmu_event_on_cpu(int cpu)
{
	struct perf_event_attr attr = {
		.freq = 1,
		.sample_freq = 1000,
		.type = PERF_TYPE_HARDWARE,
		.config = PERF_COUNT_HW_CPU_CYCLES,
	};
	int pmu_fd;

	pmu_fd = syscall(__NR_perf_event_open, &attr, -1 /* pid */, cpu,
			 -1 /* group_fd */, 0 /* flags */);
	if (pmu_fd == -1) {
		if (errno == ENOENT || errno == EOPNOTSUPP) {
			printf("%s:SKIP:no PERF_COUNT_HW_CPU_CYCLES\n", __func__);
			test__skip();
		}
		return -1;
	}

	return pmu_fd;
}

static bool pin_to_cpu(int cpu, cpu_set_t *old_cpuset)
{
	cpu_set_t cpuset;
	int err;

	err = sched_getaffinity(getpid(), sizeof(*old_cpuset), old_cpuset);
	if (!ASSERT_OK(err, "sched_getaffinity"))
		return false;

	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);
	err = sched_setaffinity(getpid(), sizeof(cpuset), &cpuset);
	if (!ASSERT_OK(err, "sched_setaffinity"))
		return false;

	return true;
}

static void restore_affinity(const cpu_set_t *old_cpuset)
{
	sched_setaffinity(getpid(), sizeof(*old_cpuset), old_cpuset);
}

static void burn_cpu(void)
{
	int i;

	/* Keep the CPU busy so PERF_COUNT_HW_CPU_CYCLES keeps raising NMIs. */
	for (i = 0; i < 1000000; i++)
		barrier();
}

static struct cgroup_kptr_nmi_deadlock_repro *open_loaded_repro_skel(void)
{
	struct cgroup_kptr_nmi_deadlock_repro *skel;
	int err;

	skel = cgroup_kptr_nmi_deadlock_repro__open();
	if (!ASSERT_OK_PTR(skel, "cgroup_kptr_nmi_deadlock_repro__open"))
		return NULL;

	err = cgroup_kptr_nmi_deadlock_repro__load(skel);
	if (!ASSERT_OK(err, "cgroup_kptr_nmi_deadlock_repro__load"))
		goto destroy_skel;

	return skel;

destroy_skel:
	cgroup_kptr_nmi_deadlock_repro__destroy(skel);
	return NULL;
}

static bool wait_for_cgroup_nmi_delete_batch(struct cgroup_kptr_nmi_deadlock_repro *skel,
					     int expected_deleted)
{
	u64 now_ns, timeout_time_ns;

	now_ns = get_time_ns();
	timeout_time_ns = now_ns + DELETE_TIMEOUT_NS;
	while (skel->bss->cgroup_kptr_nmi_deleted < expected_deleted) {
		burn_cpu();
		now_ns = get_time_ns();
		if (now_ns >= timeout_time_ns)
			break;
	}

	if (!ASSERT_EQ(skel->bss->cgroup_kptr_nmi_deleted, expected_deleted,
		       "cgroup_kptr_nmi_deleted"))
		return false;
	if (!ASSERT_LT(now_ns, timeout_time_ns,
		       "cgroup_kptr_nmi_delete_timeout"))
		return false;

	return true;
}

static bool wait_for_cgroup_css_free_batch(struct cgroup_kptr_nmi_deadlock_repro *skel,
					   int expected_done)
{
	u64 now_ns, timeout_time_ns;

	now_ns = get_time_ns();
	timeout_time_ns = now_ns + DELETE_TIMEOUT_NS;
	while (skel->bss->cgroup_kptr_nmi_killed_work_done < expected_done) {
		burn_cpu();
		now_ns = get_time_ns();
		if (now_ns >= timeout_time_ns)
			break;
	}

	if (!ASSERT_EQ(skel->bss->cgroup_kptr_nmi_killed_work_done, expected_done,
		       "cgroup_kptr_nmi_killed_work_done"))
		return false;
	if (!ASSERT_LT(now_ns, timeout_time_ns,
		       "cgroup_kptr_nmi_css_free_timeout"))
		return false;

	return true;
}

static void run_cgroup_kptr_nmi_deadlock_repro(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct cgroup_kptr_nmi_deadlock_repro *skel = NULL;
	cpu_set_t old_cpuset;
	char cgroup_path[PATH_MAX + 1];
	bool pinned = false;
	int pmu_fd = -1;
	int kmsg_fd = -1;
	int round;

	if (!ASSERT_OK(setup_cgroup_environment(), "setup_cgroup_environment"))
		return;

	skel = open_loaded_repro_skel();
	if (!skel)
		goto cleanup_cgroup_env;

	pinned = pin_to_cpu(REPRO_CPU, &old_cpuset);
	if (!pinned)
		goto destroy_skel;

	skel->links.clear_cgroup_kptrs_from_nmi =
		bpf_program__attach_trace(skel->progs.clear_cgroup_kptrs_from_nmi);
	if (!ASSERT_OK_PTR(skel->links.clear_cgroup_kptrs_from_nmi,
			   "attach_tp_btf"))
		goto destroy_skel;

	skel->links.mark_cgroup_killed_work_done =
		bpf_program__attach_trace(skel->progs.mark_cgroup_killed_work_done);
	if (!ASSERT_OK_PTR(skel->links.mark_cgroup_killed_work_done,
			   "attach_css_free_rwork_fexit"))
		goto destroy_skel;

	pmu_fd = open_nmi_pmu_event_on_cpu(REPRO_CPU);
	if (pmu_fd < 0)
		goto destroy_skel;

	kmsg_fd = open_kmsg_at_end();
	if (!ASSERT_GE(kmsg_fd, 0, "open_kmsg_at_end"))
		goto destroy_skel;

	for (round = 0; round < REPRO_ROUNDS; round++) {
		int expected_inserted = round + 1;
		int expected_css_free;
		int err;

		err = create_repro_cgroup(cgroup_path, sizeof(cgroup_path));
		if (!ASSERT_OK(err, "create_repro_cgroup"))
			goto destroy_skel;

		skel->bss->cgroup_kptr_nmi_id = get_cgroup_id(REPRO_CGROUP_REL_PATH);
		if (!ASSERT_NEQ(skel->bss->cgroup_kptr_nmi_id, 0,
				"get_cgroup_id"))
			goto destroy_skel;

		err = bpf_prog_test_run_opts(
			bpf_program__fd(skel->progs.insert_cgroup_kptr_from_syscall),
			&opts);
		if (!ASSERT_OK(err, "insert_cgroup_kptr_from_syscall"))
			goto destroy_skel;
		if (!ASSERT_EQ(opts.retval, 0,
			       "insert_cgroup_kptr_from_syscall_retval"))
			goto destroy_skel;

		if (!ASSERT_EQ(skel->bss->cgroup_kptr_nmi_err, 0,
			       "cgroup_kptr_nmi_err"))
			goto destroy_skel;
		if (!ASSERT_EQ(skel->bss->cgroup_kptr_nmi_inserted,
			       expected_inserted,
			       "cgroup_kptr_nmi_inserted"))
			goto destroy_skel;

		expected_css_free = skel->bss->cgroup_kptr_nmi_clear_runs;

		err = remove_repro_cgroup(cgroup_path);
		if (!ASSERT_OK(err, "remove_repro_cgroup"))
			goto destroy_skel;

		if (!wait_for_cgroup_css_free_batch(skel, expected_css_free))
			goto destroy_skel;

		skel->bss->cgroup_kptr_nmi_nr_cgrps = expected_inserted;
		if (!wait_for_cgroup_nmi_delete_batch(skel, expected_inserted))
			goto destroy_skel;
	}

	ASSERT_FALSE(kmsg_saw_splat(kmsg_fd), "nmi_dtor_splat");

destroy_skel:
	if (pinned)
		restore_affinity(&old_cpuset);
	close_fd(kmsg_fd);
	close_fd(pmu_fd);
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
