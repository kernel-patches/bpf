// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE

#include <errno.h>
#include <linux/perf_event.h>
#include <sched.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <test_progs.h>

#include "kptr_dtor_nmi.skel.h"

#define KPTR_DTOR_NMI_MAX_SLOTS 8
#define KPTR_DTOR_NMI_ROUNDS 256
#define DELETE_TIMEOUT_NS (5ULL * 1000 * 1000 * 1000)

enum kptr_dtor_nmi_map_type {
	KPTR_DTOR_NMI_MAP_HASH = 1,
	KPTR_DTOR_NMI_MAP_ARRAY,
};

struct kptr_dtor_nmi_case {
	const char *name;
	__u32 map_type;
};

__maybe_unused
static int find_test_cpu(void)
{
	cpu_set_t cpuset;
	int cpu, err;

	err = sched_getaffinity(0, sizeof(cpuset), &cpuset);
	if (!ASSERT_OK(err, "sched_getaffinity"))
		return -1;

	for (cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		if (CPU_ISSET(cpu, &cpuset))
			return cpu;
	}

	ASSERT_TRUE(false, "cpu_available");
	return -1;
}

__maybe_unused
static int open_nmi_pmu_event_on_cpu(int cpu)
{
	struct perf_event_attr attr = {
		.size = sizeof(attr),
		.type = PERF_TYPE_HARDWARE,
		.config = PERF_COUNT_HW_CPU_CYCLES,
		.freq = 1,
		.sample_freq = 1000,
	};
	int pmu_fd;

	pmu_fd = syscall(__NR_perf_event_open, &attr, -1, cpu, -1,
			 PERF_FLAG_FD_CLOEXEC);
	if (pmu_fd == -1) {
		if (errno == ENOENT || errno == EOPNOTSUPP) {
			printf("SKIP:no PERF_COUNT_HW_CPU_CYCLES\n");
			test__skip();
		}
		return -1;
	}

	return pmu_fd;
}

__maybe_unused
static bool pin_to_cpu(int cpu, cpu_set_t *old_cpuset)
{
	cpu_set_t cpuset;
	int err;

	err = sched_getaffinity(0, sizeof(*old_cpuset), old_cpuset);
	if (!ASSERT_OK(err, "sched_getaffinity"))
		return false;

	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);
	err = sched_setaffinity(0, sizeof(cpuset), &cpuset);
	if (!ASSERT_OK(err, "sched_setaffinity"))
		return false;

	return true;
}

__maybe_unused
static void restore_affinity(const cpu_set_t *old_cpuset)
{
	ASSERT_OK(sched_setaffinity(0, sizeof(*old_cpuset), old_cpuset),
		  "restore_affinity");
}

__maybe_unused
static bool run_syscall_prog(struct bpf_program *prog, const char *name)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err;

	err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);
	if (!ASSERT_OK(err, name))
		return false;
	if (!ASSERT_EQ(opts.retval, 0, name))
		return false;

	return true;
}

__maybe_unused
static bool wait_for_nmi_drain(struct kptr_dtor_nmi *skel,
			       __u64 expected_deleted,
			       __u64 expected_release_calls)
{
	u64 now_ns, timeout_time_ns;

	now_ns = get_time_ns();
	timeout_time_ns = now_ns + DELETE_TIMEOUT_NS;
	while (skel->bss->kptr_dtor_nmi_deleted < expected_deleted) {
		if (skel->bss->kptr_dtor_nmi_setup_err ||
		    skel->bss->kptr_dtor_nmi_nmi_err ||
		    skel->bss->kptr_dtor_nmi_cleanup_err)
			break;
		now_ns = get_time_ns();
		if (now_ns >= timeout_time_ns)
			break;
		sched_yield();
	}

	if (!ASSERT_EQ(skel->bss->kptr_dtor_nmi_setup_err, 0,
		       "kptr_dtor_nmi_setup_err"))
		return false;
	if (!ASSERT_EQ(skel->bss->kptr_dtor_nmi_nmi_err, 0,
		       "kptr_dtor_nmi_nmi_err"))
		return false;
	if (!ASSERT_EQ(skel->bss->kptr_dtor_nmi_cleanup_err, 0,
		       "kptr_dtor_nmi_cleanup_err"))
		return false;
	if (!ASSERT_GE(skel->bss->kptr_dtor_nmi_deleted, expected_deleted,
		       "kptr_dtor_nmi_deleted"))
		return false;
	if (!ASSERT_OK(kern_sync_rcu(), "kern_sync_rcu"))
		return false;
	if (!ASSERT_GE(skel->bss->kptr_dtor_nmi_release_calls,
		       expected_release_calls,
		       "kptr_dtor_nmi_release_calls"))
		return false;
	if (!ASSERT_LT(now_ns, timeout_time_ns, "kptr_dtor_nmi_timeout"))
		return false;

	return true;
}

__maybe_unused
static void run_kptr_dtor_nmi_case(const struct kptr_dtor_nmi_case *test)
{
	struct kptr_dtor_nmi *skel;
	cpu_set_t old_cpuset;
	bool pinned = false;
	int cpu = -1;
	int pmu_fd = -1;
	int err, round;

	cpu = find_test_cpu();
	if (cpu < 0)
		return;

	skel = kptr_dtor_nmi__open();
	if (!ASSERT_OK_PTR(skel, "kptr_dtor_nmi__open"))
		return;

	skel->bss->kptr_dtor_nmi_map_type = test->map_type;
	bpf_program__set_autoattach(skel->progs.clear_kptrs_from_nmi, false);

	err = kptr_dtor_nmi__load(skel);
	if (!ASSERT_OK(err, "kptr_dtor_nmi__load"))
		goto cleanup;

	err = kptr_dtor_nmi__attach(skel);
	if (!ASSERT_OK(err, "kptr_dtor_nmi__attach"))
		goto cleanup;

	skel->links.clear_kptrs_from_nmi =
		bpf_program__attach_trace(skel->progs.clear_kptrs_from_nmi);
	if (!ASSERT_OK_PTR(skel->links.clear_kptrs_from_nmi,
			   "attach_tp_btf_nmi_handler"))
		goto cleanup;

	pinned = pin_to_cpu(cpu, &old_cpuset);
	if (!pinned)
		goto cleanup;

	pmu_fd = open_nmi_pmu_event_on_cpu(cpu);
	if (pmu_fd < 0)
		goto cleanup;

	for (round = 0; round < KPTR_DTOR_NMI_ROUNDS; round++) {
		__u64 expected_total;

		if (!run_syscall_prog(skel->progs.populate_kptrs, "populate_kptrs"))
			goto cleanup;

		expected_total = (round + 1) * KPTR_DTOR_NMI_MAX_SLOTS;
		if (!ASSERT_EQ(skel->bss->kptr_dtor_nmi_setup_created,
			       expected_total,
			       "kptr_dtor_nmi_setup_created"))
			goto cleanup;

		if (!wait_for_nmi_drain(skel, expected_total, expected_total))
			goto cleanup;
	}

	if (!run_syscall_prog(skel->progs.cleanup_kptrs, "cleanup_kptrs"))
		goto cleanup;
	/*
	 * The grace period for rcu cannot complete until the CPU that ran the
	 * hard irq_work has passed through a quiescent state after running
	 * our dtor work. This effectively flushes our pending work and allows
	 * the test to verify the dtor was called the expected number of times.
	 */
	kern_sync_rcu();
	ASSERT_EQ(skel->bss->kptr_dtor_nmi_cleanup_deleted, 0,
		  "kptr_dtor_nmi_cleanup_deleted");

cleanup:
	if (pmu_fd >= 0)
		close(pmu_fd);
	if (pinned)
		restore_affinity(&old_cpuset);
	kptr_dtor_nmi__destroy(skel);
}

void serial_test_kptr_dtor_nmi(void)
{
/*
 * nmi_handler isn't supported for these architectures.
 */
#if defined(__aarch64__) || defined(__s390x__)
	test__skip();
	return;
#else
	static const struct kptr_dtor_nmi_case tests[] = {
		{ "hash", KPTR_DTOR_NMI_MAP_HASH },
		{ "array", KPTR_DTOR_NMI_MAP_ARRAY },
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		if (!test__start_subtest(tests[i].name))
			continue;
		run_kptr_dtor_nmi_case(&tests[i]);
	}
#endif
}
