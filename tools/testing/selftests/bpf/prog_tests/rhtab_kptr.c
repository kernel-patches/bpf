// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 KylinSoft Co., Ltd. */

#include <test_progs.h>
#include <linux/perf_event.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "rhtab_kptr.skel.h"

/* Userspace mirror of the BPF-side struct val_t (progs/rhtab_kptr.c). The
 * update syscall copies map->value_size bytes from the buffer, so it must
 * be at least that large; special fields are skipped by the value copy but
 * the kernel still reads the full value_size from userspace.
 */
struct val_t_user {
	__u64 tsk;
	__u32 magic;
	__u32 pad;
};

_Static_assert(sizeof(struct val_t_user) == 16, "val_t layout drift");
_Static_assert(offsetof(struct val_t_user, magic) == 8, "val_t magic offset drift");

/* Zeroed value for creating/recreating elements; BSS is zero-filled. */
static struct val_t_user zero;

/* Cached CPU count and scratch buffer for percpu counter summation. */
static __u64 *cpu_vals;
static int ncpu = -1;

static __u64 read_counter(struct rhtab_kptr *skel, u32 idx)
{
	__u64 sum = 0;
	int i, err;

	if (!cpu_vals)
		return 0;
	err = bpf_map_lookup_elem(bpf_map__fd(skel->maps.counters), &idx,
				  cpu_vals);
	if (!ASSERT_OK(err, "lookup_counter"))
		return 0;
	for (i = 0; i < ncpu; i++)
		sum += cpu_vals[i];
	return sum;
}

/* Run @name via BPF_PROG_TEST_RUN, asserting both the syscall status and
 * that the program exited 0. Returns 0 on success.
 */
static int run_prog_ok(struct rhtab_kptr *skel, const char *name)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct bpf_program *prog;
	int err;

	prog = bpf_object__find_program_by_name(skel->obj, name);
	if (!ASSERT_OK_PTR(prog, name))
		return -1;
	err = bpf_prog_test_run_opts(bpf_program__fd(prog), &topts);
	if (!ASSERT_OK(err, name))
		return -1;
	if (!ASSERT_EQ(topts.retval, 0, name))
		return -1;
	return 0;
}

void test_rhtab_kptr(void)
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_HARDWARE,
		.config = PERF_COUNT_HW_CPU_CYCLES,
		.freq = 1,
		.sample_freq = read_perf_max_sample_freq(),
		.size = sizeof(struct perf_event_attr),
	};
	struct rhtab_kptr *skel;
	__u64 init_before, nonnull_before;
	__u32 key = 0;
	int pmu_fd, i, retries = 0;

	ncpu = libbpf_num_possible_cpus();
	if (!ASSERT_GT(ncpu, 0, "num_possible_cpus"))
		return;
	cpu_vals = calloc(ncpu, sizeof(*cpu_vals));
	if (!ASSERT_OK_PTR(cpu_vals, "calloc_cpu_vals"))
		return;

	skel = rhtab_kptr__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto out_free;

	/* Create the element and stash a referenced task kptr in it. */
	if (!ASSERT_OK(bpf_map_update_elem(bpf_map__fd(skel->maps.rhtab),
					   &key, &zero, BPF_ANY), "create_elem"))
		goto out;
	if (run_prog_ok(skel, "init_elem") != 0)
		goto out;

	pmu_fd = syscall(__NR_perf_event_open, &attr, -1, 0, -1, 0);
	if (pmu_fd >= 0) {
		skel->links.nmi_update = bpf_program__attach_perf_event(skel->progs.nmi_update,
									pmu_fd);
		if (!ASSERT_OK_PTR(skel->links.nmi_update, "attach_perf_event")) {
			close(pmu_fd);
			goto out;
		}

		/* Let the NMI handler overwrite the element, and make sure it
		 * actually ran before probing (otherwise the probe would pass
		 * vacuously even on an unfixed kernel).
		 */
		for (i = 0; i < 20 && read_counter(skel, 1) == 0; i++)
			usleep(100000);
		ASSERT_GT(read_counter(skel, 1), 0, "nmi_update_ran");

		bpf_link__destroy(skel->links.nmi_update);
		skel->links.nmi_update = NULL;
		close(pmu_fd);

		/*
		 * The old kptr must still be attached to the element: the
		 * NMI update path only cancels NMI-safe fields, mirroring
		 * hash map semantics. Before the fix the kptr was released
		 * from the NMI context and the probe below would see NULL.
		 */
		if (run_prog_ok(skel, "probe_elem") != 0)
			goto out;

		ASSERT_EQ(read_counter(skel, 2), 1, "xchg_non_null");
		ASSERT_EQ(read_counter(skel, 3), 0, "xchg_null");
	} else {
		test__skip();
	}

	/*
	 * Now exercise the delete/re-insert recycle path. The delete only
	 * cancels NMI-safe fields, so the freed element still owns the kptr.
	 * If the re-insertion recycles that element, the kptr must be
	 * inherited; zeroing it (as check_and_init_map_value() did before
	 * the fix) leaks the reference and probe_elem() observes NULL.
	 * Fresh memory handed out by the allocator is zeroed, so NULL probes
	 * are expected too; only require that the inherited kptr survives at
	 * least one recycle. Every iteration runs exactly one probe, so the
	 * counters must add up to the loop count.
	 */
	init_before = read_counter(skel, 0);
	nonnull_before = read_counter(skel, 2);
	for (i = 0; i < 2000; i++) {
		if (run_prog_ok(skel, "init_elem") != 0) {
			/* init_elem fails only if the element is missing,
			 * which must not happen in this single-threaded
			 * loop; count it so a rhtab bug cannot be absorbed
			 * silently.
			 */
			retries++;
			if (!ASSERT_OK(bpf_map_update_elem(bpf_map__fd(skel->maps.rhtab),
							   &key, &zero, BPF_ANY),
				       "recreate_elem"))
				goto out;
			if (run_prog_ok(skel, "init_elem") != 0)
				goto out;
		}
		if (run_prog_ok(skel, "del_elem") != 0 ||
		    run_prog_ok(skel, "upd_elem") != 0 ||
		    run_prog_ok(skel, "probe_elem") != 0)
			goto out;
	}

	/*
	 * Plain (non-special) value bytes must survive the recycle path:
	 * every probe must observe the magic value written by upd_elem() in
	 * the same iteration, regardless of whether the element memory was
	 * recycled or freshly allocated.
	 */
	ASSERT_EQ(retries, 0, "no_unexpected_recreate");
	ASSERT_EQ(read_counter(skel, 0) - init_before, 2000, "init_loop_count");
	ASSERT_EQ(read_counter(skel, 4), 2000, "recycle_magic_roundtrip");
	ASSERT_GT(read_counter(skel, 2), nonnull_before, "recycle_xchg_non_null");
out:
	rhtab_kptr__destroy(skel);
out_free:
	free(cpu_vals);
}
