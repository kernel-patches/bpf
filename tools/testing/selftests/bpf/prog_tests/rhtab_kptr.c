// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 KylinSoft Co., Ltd. */

#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <test_progs.h>
#include "rhtab_kptr.skel.h"

static __u64 read_counter(struct rhtab_kptr *skel, u32 idx)
{
	__u64 vals[libbpf_num_possible_cpus()];
	__u64 sum = 0;
	int i, err;

	err = bpf_map_lookup_elem(bpf_map__fd(skel->maps.counters), &idx, vals);
	if (!ASSERT_OK(err, "lookup_counter"))
		return 0;
	for (i = 0; i < libbpf_num_possible_cpus(); i++)
		sum += vals[i];
	return sum;
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
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct rhtab_kptr *skel;
	__u32 key = 0;
	__u64 zero = 0;
	__u64 nonnull_before;
	int pmu_fd, i, err;

	skel = rhtab_kptr__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	/* Create the element and stash a referenced task kptr in it. */
	if (!ASSERT_OK(bpf_map_update_elem(bpf_map__fd(skel->maps.rhtab),
					   &key, &zero, BPF_ANY), "create_elem"))
		goto out;
	if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(skel->progs.init_elem),
					      &topts), "test_run_init") ||
	    !ASSERT_EQ(topts.retval, 0, "init_ret"))
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
		topts.retval = 0;
		if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(skel->progs.probe_elem),
						      &topts), "test_run_probe") ||
		    !ASSERT_EQ(topts.retval, 0, "probe_ret"))
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
	 * least one recycle.
	 */
	nonnull_before = read_counter(skel, 2);
	for (i = 0; i < 2000; i++) {
		topts.retval = 0;
		err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.init_elem),
					     &topts);
		if (err || topts.retval) {
			/* Element may be gone; recreate and retry once. */
			if (!ASSERT_OK(bpf_map_update_elem(bpf_map__fd(skel->maps.rhtab),
							   &key, &zero, BPF_ANY),
				       "recreate_elem"))
				goto out;
			topts.retval = 0;
			err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.init_elem),
						     &topts);
		}
		if (!ASSERT_OK(err, "test_run_init_loop") ||
		    !ASSERT_EQ(topts.retval, 0, "init_loop_ret"))
			goto out;

		topts.retval = 0;
		if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(skel->progs.del_elem),
						      &topts), "test_run_del"))
			goto out;
		topts.retval = 0;
		if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(skel->progs.upd_elem),
						      &topts), "test_run_upd"))
			goto out;
		topts.retval = 0;
		if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(skel->progs.probe_elem),
						      &topts), "test_run_probe"))
			goto out;
	}

	/*
	 * Plain (non-special) value bytes must survive the recycle path:
	 * every probe must observe the magic value written by upd_elem() in
	 * the same iteration, regardless of whether the element memory was
	 * recycled or freshly allocated.
	 */
	ASSERT_EQ(read_counter(skel, 4), 2000, "recycle_magic_roundtrip");

	ASSERT_GT(read_counter(skel, 2), nonnull_before, "recycle_xchg_non_null");
out:
	rhtab_kptr__destroy(skel);
}
