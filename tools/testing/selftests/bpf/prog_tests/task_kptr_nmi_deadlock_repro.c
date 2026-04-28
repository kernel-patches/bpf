// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <bpf/btf.h>
#include <test_progs.h>

#include "task_kptr_nmi_deadlock_repro.skel.h"

#define STASHED_TASKS 4
#define DELETE_TIMEOUT_NS (5ULL * 1000 * 1000 * 1000)
#define REPRO_ROUNDS 256

enum task_kptr_nmi_map_type {
	TASK_KPTR_NMI_MAP_HASH = 1,
	TASK_KPTR_NMI_MAP_ARRAY,
};

enum task_kptr_nmi_err {
	TASK_KPTR_NMI_ACQUIRE_ERR = 1,
	TASK_KPTR_NMI_CREATE_ERR,
	TASK_KPTR_NMI_LOOKUP_ERR,
	TASK_KPTR_NMI_MAP_ERR,
};

struct task_kptr_nmi_repro_case {
	const char *name;
	__u32 map_type;
};

static int find_test_cpu(void)
{
	cpu_set_t cpuset;
	int cpu, err;

	err = sched_getaffinity(0, sizeof(cpuset), &cpuset);
	if (!ASSERT_OK(err, "sched_getaffinity"))
		return -1;

	for (cpu = 1; cpu < CPU_SETSIZE; cpu++) {
		if (CPU_ISSET(cpu, &cpuset))
			return cpu;
	}

	ASSERT_TRUE(false, "cpu_available");
	return -1;
}

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

	pmu_fd = syscall(__NR_perf_event_open, &attr, -1 /* pid */, cpu,
			 -1 /* group_fd */, PERF_FLAG_FD_CLOEXEC);
	if (pmu_fd == -1) {
		if (errno == ENOENT || errno == EOPNOTSUPP) {
			printf("SKIP:no PERF_COUNT_HW_CPU_CYCLES\n");
			test__skip();
		}
		return -1;
	}

	return pmu_fd;
}

static bool has_nmi_handler_btf(void)
{
	struct btf *btf;
	int id;

	btf = btf__load_vmlinux_btf();
	if (libbpf_get_error(btf)) {
		printf("SKIP:no vmlinux BTF\n");
		test__skip();
		return false;
	}

	id = btf__find_by_name_kind(btf, "nmi_handler", BTF_KIND_FUNC);
	btf__free(btf);
	if (id <= 0) {
		printf("SKIP:no BTF FUNC nmi_handler\n");
		test__skip();
		return false;
	}

	return true;
}

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

static void restore_affinity(const cpu_set_t *old_cpuset)
{
	ASSERT_OK(sched_setaffinity(0, sizeof(*old_cpuset), old_cpuset),
		  "restore_affinity");
}

static bool stash_exited_tasks(struct task_kptr_nmi_deadlock_repro *skel)
{
	int i, status;

	for (i = 0; i < STASHED_TASKS; i++) {
		int pipefd[2];
		char sync;
		pid_t child_pid;

		if (!ASSERT_OK(pipe2(pipefd, O_CLOEXEC), "pipe2"))
			return false;

		child_pid = fork();
		if (!ASSERT_GT(child_pid, -1, "fork")) {
			close(pipefd[0]);
			close(pipefd[1]);
			return false;
		}

		if (child_pid == 0) {
			char sync;
			int fd;

			close(pipefd[1]);
			if (read(pipefd[0], &sync, 1) != 1)
				_exit(127);
			close(pipefd[0]);
			fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
			if (fd < 0)
				_exit(127);
			close(fd);
			_exit(0);
		}

		close(pipefd[0]);
		skel->bss->task_kptr_nmi_pids[i] = child_pid;

		sync = 1;
		if (!ASSERT_EQ(write(pipefd[1], &sync, 1), 1, "start_child")) {
			close(pipefd[1]);
			waitpid(child_pid, &status, 0);
			return false;
		}
		close(pipefd[1]);

		if (!ASSERT_EQ(waitpid(child_pid, &status, 0), child_pid,
			       "waitpid"))
			return false;
		if (!ASSERT_TRUE(WIFEXITED(status), "child_exited"))
			return false;
		if (!ASSERT_EQ(WEXITSTATUS(status), 0, "child_status"))
			return false;
	}

	return true;
}

static bool
wait_for_task_nmi_delete_batch(struct task_kptr_nmi_deadlock_repro *skel,
			       int expected_deleted)
{
	u64 now_ns, timeout_time_ns;
	unsigned long burn = 0;
	int i;

	now_ns = get_time_ns();
	timeout_time_ns = now_ns + DELETE_TIMEOUT_NS;
	for (i = 0; skel->bss->task_kptr_nmi_deleted < expected_deleted; i++) {
		int j;

		if (skel->bss->task_kptr_nmi_delete_err)
			break;
		for (j = 0; j < 1000000; j++)
			burn += j + i;
		now_ns = get_time_ns();
		if (now_ns >= timeout_time_ns)
			break;
	}

	if (!ASSERT_EQ(skel->bss->task_kptr_nmi_delete_err, 0,
		       "task_kptr_nmi_delete_err"))
		return false;
	if (!ASSERT_GE(skel->bss->task_kptr_nmi_deleted, expected_deleted,
		       "task_kptr_nmi_deleted"))
		return false;
	if (!ASSERT_LT(now_ns, timeout_time_ns, "task_kptr_nmi_delete_timeout"))
		return false;

	return true;
}

static void run_task_kptr_nmi_deadlock_repro_case(const struct task_kptr_nmi_repro_case *test)
{
	struct task_kptr_nmi_deadlock_repro *skel;
	cpu_set_t old_cpuset;
	bool pinned = false;
	__u32 expected_deleted = 0;
	int cpu = -1;
	int pmu_fd = -1;
	int err, round;

	if (!has_nmi_handler_btf())
		return;

	cpu = find_test_cpu();
	if (cpu < 0)
		return;

	skel = task_kptr_nmi_deadlock_repro__open();
	if (!ASSERT_OK_PTR(skel, "task_kptr_nmi_deadlock_repro__open"))
		return;

	skel->bss->task_kptr_nmi_map_type = test->map_type;
	bpf_program__set_autoload(skel->progs.clear_task_kptrs_from_nmi, true);

	err = task_kptr_nmi_deadlock_repro__load(skel);
	if (!ASSERT_OK(err, "task_kptr_nmi_deadlock_repro__load"))
		goto cleanup;

	if (bpf_program__fd(skel->progs.clear_task_kptrs_from_nmi) < 0) {
		test__skip();
		goto cleanup;
	}

	err = task_kptr_nmi_deadlock_repro__attach(skel);
	if (!ASSERT_OK(err, "task_kptr_nmi_deadlock_repro__attach"))
		goto cleanup;

	pinned = pin_to_cpu(cpu, &old_cpuset);
	if (!pinned)
		goto cleanup;

	pmu_fd = open_nmi_pmu_event_on_cpu(cpu);
	if (pmu_fd < 0)
		goto cleanup;

	for (round = 0; round < REPRO_ROUNDS; round++) {
		if (!stash_exited_tasks(skel))
			goto cleanup;

		/*
		 * Hash map inserts create an empty element before looking it up
		 * to stash the task kptr. NMI cleanup can delete that fresh
		 * element in between, so LOOKUP_ERR here is a benign test race
		 * and not a kernel failure.
		 */
		if (test->map_type == TASK_KPTR_NMI_MAP_HASH &&
		    skel->bss->task_kptr_nmi_err == TASK_KPTR_NMI_LOOKUP_ERR)
			skel->bss->task_kptr_nmi_err = 0;

		if (!ASSERT_EQ(skel->bss->task_kptr_nmi_err, 0, "task_kptr_nmi_err"))
			goto cleanup;
		expected_deleted = skel->bss->task_kptr_nmi_inserted;
		if (!wait_for_task_nmi_delete_batch(skel, expected_deleted))
			goto cleanup;
	}

cleanup:
	close(pmu_fd);
	if (pinned)
		restore_affinity(&old_cpuset);
	task_kptr_nmi_deadlock_repro__destroy(skel);
}

void serial_test_task_kptr_nmi_deadlock_repro(void)
{
	static const struct task_kptr_nmi_repro_case tests[] = {
		{ "hash", TASK_KPTR_NMI_MAP_HASH },
		{ "array", TASK_KPTR_NMI_MAP_ARRAY },
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		if (!test__start_subtest(tests[i].name))
			continue;
		run_task_kptr_nmi_deadlock_repro_case(&tests[i]);
	}
}
