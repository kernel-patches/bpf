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
	int pmu_fd;

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
	if (pmu_fd < 0) {
		test__skip();
		goto out;
	}
	skel->links.nmi_update = bpf_program__attach_perf_event(skel->progs.nmi_update,
								pmu_fd);
	if (!ASSERT_OK_PTR(skel->links.nmi_update, "attach_perf_event")) {
		close(pmu_fd);
		goto out;
	}

	/* Let the NMI handler overwrite the element. */
	usleep(100000);

	bpf_link__destroy(skel->links.nmi_update);
	skel->links.nmi_update = NULL;
	close(pmu_fd);

	/*
	 * The old kptr must still be attached to the element: the NMI update
	 * path only cancels NMI-safe fields, mirroring hash map semantics.
	 * Before the fix the kptr was released from the NMI context and the
	 * probe below would see NULL.
	 */
	topts.retval = 0;
	if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(skel->progs.probe_elem),
					      &topts), "test_run_probe") ||
	    !ASSERT_EQ(topts.retval, 0, "probe_ret"))
		goto out;

	ASSERT_EQ(read_counter(skel, 2), 1, "xchg_non_null");
	ASSERT_EQ(read_counter(skel, 3), 0, "xchg_null");
out:
	rhtab_kptr__destroy(skel);
}
