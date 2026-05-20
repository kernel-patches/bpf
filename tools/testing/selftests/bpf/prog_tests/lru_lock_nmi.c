// SPDX-License-Identifier: GPL-2.0
/*
 * Stress the BPF LRU hash map from both syscall context and a perf-event
 * NMI BPF program on the same CPU. Before commit converting the LRU
 * per-CPU local list lock to rqspinlock, this triggered a lockdep
 * "inconsistent {INITIAL USE} -> {IN-NMI}" splat on &loc_l->lock.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <test_progs.h>
#include "testing_helpers.h"
#include "lru_lock_nmi.skel.h"

#define BURN_NS	(200 * 1000 * 1000ULL)

static void hammer_map(int map_fd, __u64 deadline_ns)
{
	__u64 val = 1;
	__u32 key;

	while (get_time_ns() < deadline_ns) {
		key = rand();
		bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);
	}
}

void serial_test_lru_lock_nmi(void)
{
	struct perf_event_attr attr = {
		.size = sizeof(attr),
		.type = PERF_TYPE_HARDWARE,
		.config = PERF_COUNT_HW_CPU_CYCLES,
		.freq = 1,
	};
	struct lru_lock_nmi *skel = NULL;
	int pmu_fd = -1, map_fd, err;
	cpu_set_t cpu_set;

	/*
	 * Pin to CPU 0 so the syscall hammer and the NMI handler race on
	 * the same per-CPU loc_l->lock.
	 */
	CPU_ZERO(&cpu_set);
	CPU_SET(0, &cpu_set);
	err = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set), &cpu_set);
	if (!ASSERT_OK(err, "setaffinity"))
		return;

	attr.sample_freq = read_perf_max_sample_freq();

	pmu_fd = syscall(__NR_perf_event_open, &attr, 0 /* pid */, -1 /* cpu */,
			 -1 /* group */, 0 /* flags */);
	if (pmu_fd < 0 && (errno == ENOENT || errno == EOPNOTSUPP)) {
		test__skip();
		return;
	}
	if (!ASSERT_GE(pmu_fd, 0, "perf_event_open"))
		return;

	skel = lru_lock_nmi__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_load"))
		goto cleanup;

	skel->links.oncpu = bpf_program__attach_perf_event(skel->progs.oncpu,
							   pmu_fd);
	if (!ASSERT_OK_PTR(skel->links.oncpu, "attach_perf_event"))
		goto cleanup;

	map_fd = bpf_map__fd(skel->maps.lru_map);
	hammer_map(map_fd, get_time_ns() + BURN_NS);

	ASSERT_GT(skel->bss->hits, 0, "nmi_bpf_ran");

cleanup:
	if (pmu_fd >= 0)
		close(pmu_fd);
	lru_lock_nmi__destroy(skel);
}
