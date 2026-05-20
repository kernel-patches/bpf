// SPDX-License-Identifier: GPL-2.0
/*
 * Stress every LRU lock-failure and orphan-recovery branch added by the
 * rqspinlock conversion. perf_event NMI BPF on every online CPU does
 * update+delete on a small LRU map; userspace threads on every CPU do
 * the same from syscall context. Exercises:
 *
 *   - per-CPU loc_l->lock NMI re-entry (the original syzbot deadlock)
 *   - cross-CPU steal-loop victim lock contention
 *   - post-steal local lock contention and free_llist recovery
 *   - push_free lock failure and pending_free recovery via flush,
 *     shrink_inactive, and the new __local_list_pop_pending path
 *
 * Runs against three map flavors:
 *   - BPF_MAP_TYPE_LRU_HASH (common LRU)
 *   - BPF_MAP_TYPE_LRU_HASH | BPF_F_NO_COMMON_LRU (per-CPU LRU lists,
 *     common values)
 *   - BPF_MAP_TYPE_LRU_PERCPU_HASH (per-CPU LRU + per-CPU values)
 *
 * Post-stress: every map slot must be re-allocatable, proving no node
 * was permanently stranded by a failed push_free recovery. Transient
 * -ENOMEM during the drain is allowed and retried.
 *
 * With PROVE_LOCKING enabled, the pre-fix kernel fires a lockdep splat
 * during stress; the framework's dmesg capture surfaces it.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <test_progs.h>
#include "testing_helpers.h"
#include "lru_lock_nmi.skel.h"

#define MAP_ENTRIES	64
#define KEY_RANGE	(MAP_ENTRIES * 2)	/* wider than capacity to force eviction */
#define STRESS_NS	(500 * 1000 * 1000ULL)

struct hammer_arg {
	int map_fd;
	int cpu;
	int nr_cpus;
	__u64 deadline_ns;
};

static void *hammer_thread(void *p)
{
	struct hammer_arg *a = p;
	__u64 val[a->nr_cpus];
	cpu_set_t cs;
	__u32 key;

	memset(val, 0, sizeof(val));
	CPU_ZERO(&cs);
	CPU_SET(a->cpu, &cs);
	pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);

	while (get_time_ns() < a->deadline_ns) {
		bool do_update = rand() & 1;

		key = rand() % KEY_RANGE;
		if (do_update)
			bpf_map_update_elem(a->map_fd, &key, val, BPF_ANY);
		else
			bpf_map_delete_elem(a->map_fd, &key);
	}
	return NULL;
}

/*
 * After stress, the map must accept MAP_ENTRIES fresh allocations.
 * A node permanently stranded by a failed push_free recovery would
 * surface as -ENOMEM from update_elem: shrink_inactive cannot find
 * either a pending_free=1 marker or a del_from_htab=true elem.
 * No retry needed - by the time drain runs, NMI is detached and no
 * userspace contention is present, so every update either pulls
 * from FREE or evicts a previously-added entry on the same CPU.
 */
static int drain_and_refill(int map_fd, int nr_cpus)
{
	__u64 val[nr_cpus];
	__u32 key;

	memset(val, 0, sizeof(val));
	for (key = 0; key < KEY_RANGE; key++)
		bpf_map_delete_elem(map_fd, &key);

	for (key = 0; key < MAP_ENTRIES; key++)
		if (bpf_map_update_elem(map_fd, &key, val, BPF_ANY))
			return -ENOMEM;
	return 0;
}

static void run_variant(enum bpf_map_type type, __u32 map_flags,
			const char *name)
{
	struct perf_event_attr attr = {
		.size = sizeof(attr),
		.type = PERF_TYPE_HARDWARE,
		.config = PERF_COUNT_HW_CPU_CYCLES,
		.freq = 1,
	};
	int nr_cpus = libbpf_num_possible_cpus();
	int pmu_fds[nr_cpus];
	struct bpf_link *links[nr_cpus];
	pthread_t threads[nr_cpus];
	struct hammer_arg args[nr_cpus];
	struct lru_lock_nmi *skel = NULL;
	int map_fd, i, err, nr_threads = 0;
	__u64 deadline;

	if (!test__start_subtest(name))
		return;

	memset(pmu_fds, 0xff, sizeof(pmu_fds));	/* -1 sentinel */
	memset(links, 0, sizeof(links));

	skel = lru_lock_nmi__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		goto cleanup;

	err = bpf_map__set_type(skel->maps.lru_map, type);
	if (!ASSERT_OK(err, "set_type"))
		goto cleanup;
	err = bpf_map__set_map_flags(skel->maps.lru_map, map_flags);
	if (!ASSERT_OK(err, "set_flags"))
		goto cleanup;
	err = bpf_map__set_max_entries(skel->maps.lru_map, MAP_ENTRIES);
	if (!ASSERT_OK(err, "set_max_entries"))
		goto cleanup;

	err = lru_lock_nmi__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto cleanup;

	skel->bss->hits = 0;
	map_fd = bpf_map__fd(skel->maps.lru_map);
	attr.sample_freq = read_perf_max_sample_freq();

	for (i = 0; i < nr_cpus; i++) {
		pmu_fds[i] = syscall(__NR_perf_event_open, &attr, -1, i,
				     -1, 0);
		if (pmu_fds[i] < 0) {
			if (i == 0 &&
			    (errno == ENOENT || errno == EOPNOTSUPP)) {
				test__skip();
				goto cleanup;
			}
			continue;
		}
		links[i] = bpf_program__attach_perf_event(skel->progs.oncpu,
							  pmu_fds[i]);
		if (!links[i]) {
			close(pmu_fds[i]);
			pmu_fds[i] = -1;
		}
	}

	deadline = get_time_ns() + STRESS_NS;
	for (i = 0; i < nr_cpus; i++) {
		args[i].map_fd = map_fd;
		args[i].cpu = i;
		args[i].nr_cpus = nr_cpus;
		args[i].deadline_ns = deadline;
		if (pthread_create(&threads[nr_threads], NULL, hammer_thread,
				   &args[i]) == 0)
			nr_threads++;
	}
	for (i = 0; i < nr_threads; i++)
		pthread_join(threads[i], NULL);

	for (i = 0; i < nr_cpus; i++) {
		if (links[i]) {
			bpf_link__destroy(links[i]);
			links[i] = NULL;
		}
		if (pmu_fds[i] >= 0) {
			close(pmu_fds[i]);
			pmu_fds[i] = -1;
		}
	}

	ASSERT_GT(skel->bss->hits, 0, "nmi_bpf_ran");
	ASSERT_OK(drain_and_refill(map_fd, nr_cpus), "drain_and_refill");

cleanup:
	for (i = 0; i < nr_cpus; i++) {
		if (links[i])
			bpf_link__destroy(links[i]);
		if (pmu_fds[i] >= 0)
			close(pmu_fds[i]);
	}
	lru_lock_nmi__destroy(skel);
}

void serial_test_lru_lock_nmi(void)
{
	run_variant(BPF_MAP_TYPE_LRU_HASH, 0, "common_lru");
	run_variant(BPF_MAP_TYPE_LRU_HASH, BPF_F_NO_COMMON_LRU, "no_common_lru");
	run_variant(BPF_MAP_TYPE_LRU_PERCPU_HASH, 0, "percpu_lru");
}
