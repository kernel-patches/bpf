// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2019 Facebook */
#include <pthread.h>
#include <sched.h>
#include <test_progs.h>
#include <linux/bpf.h>
#include "test_perf_event_helpers.skel.h"

static int setup_and_run(struct bpf_map *map, struct bpf_program *prog)
{
	int err, key = 0, pfd = -1;
	DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct perf_event_attr attr = {
		.size = sizeof(struct perf_event_attr),
		.type = PERF_TYPE_SOFTWARE,
		.config = PERF_COUNT_SW_CPU_CLOCK,
	};

	pfd = syscall(__NR_perf_event_open, &attr, 0 /* pid */,
		      -1 /* cpu 0 */, -1 /* group id */, 0 /* flags */);
	if (!ASSERT_GT(pfd, 0, "perf_event_open"))
		return pfd;

	err = bpf_map_update_elem(bpf_map__fd(map), &key, &pfd, BPF_ANY);
	close(pfd);
	if (!ASSERT_OK(err, "bpf_map_update_elem"))
		return err;

	err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);
	if (!ASSERT_OK(err, "bpf_prog_test_run_opts"))
		return err;

	return opts.retval;
}

static void test_one_map(struct bpf_map *map, struct bpf_program *prog,
			 bool has_share_pe)
{
	int err, retval;
	DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts);

	retval = setup_and_run(map, prog);
	if (!ASSERT_EQ(retval, 0, "bpf_perf_event_read_value"))
		return;

	/* closing mfd, prog still holds a reference on map */
	close(bpf_map__fd(map));

	err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);
	if (!ASSERT_OK(err, "bpf_prog_test_run_opts"))
		return;

	if (has_share_pe)
		ASSERT_OK(opts.retval, "bpf_perf_event_read_value");
	else
		ASSERT_EQ(opts.retval, -ENOENT, "bpf_perf_event_read_value");
}

/* bpf_perf_event_read() returns the counter value directly, not an error. */
static void test_legacy_read(struct bpf_map *map, struct bpf_program *prog)
{
	int retval = setup_and_run(map, prog);

	ASSERT_GT(retval, 0, "bpf_perf_event_read");
}

static noinline int read_value_func_1(void)
{
	static int val = 1;

	val += 1;
	usleep(100);

	return val;
}

static noinline int read_value_func_2(void)
{
	return read_value_func_1();
}

static noinline int read_value_func_3(void)
{
	return read_value_func_2();
}

static void read_value_work(void)
{
	int i, val = 1;

	for (i = 0; i < 100; i++)
		val += read_value_func_3();
}

static void test_prog_read_value(struct test_perf_event_helpers *skel)
{
	struct perf_event_attr attr = {
		.size = sizeof(struct perf_event_attr),
		.type = PERF_TYPE_HARDWARE,
		.config = PERF_COUNT_HW_CPU_CYCLES,
		.sample_type = PERF_SAMPLE_IP,
		.freq = 1,
		.sample_freq = read_perf_max_sample_freq(),
	};
	struct bpf_link *link;
	cpu_set_t cpu_set;
	int pfd;

	CPU_ZERO(&cpu_set);
	CPU_SET(0, &cpu_set);
	if (!ASSERT_OK(pthread_setaffinity_np(pthread_self(), sizeof(cpu_set), &cpu_set),
		       "set_affinity"))
		return;

	pfd = syscall(__NR_perf_event_open, &attr, -1 /* pid */,
		      0 /* cpu */, -1 /* group id */, 0 /* flags */);
	if (pfd < 0) {
		printf("%s:SKIP:perf_event_open failed (errno %d)\n", __func__, errno);
		test__skip();
		return;
	}

	link = bpf_program__attach_perf_event(skel->progs.read_prog_value, pfd);
	if (!ASSERT_OK_PTR(link, "attach_perf_event")) {
		close(pfd);
		return;
	}

	read_value_work();

	ASSERT_OK(skel->data->read_prog_value_ret, "bpf_perf_prog_read_value");
	ASSERT_GT(skel->bss->read_prog_value_enabled, 0, "read_prog_value_enabled");
	ASSERT_GT(skel->bss->read_prog_value_running, 0, "read_prog_value_running");

	bpf_link__destroy(link);
}

void test_perf_event_helpers(void)
{
	struct test_perf_event_helpers *skel;

	skel = test_perf_event_helpers__open_and_load();
	if (!ASSERT_OK_PTR(skel, "failed to open skeleton\n"))
		return;

	if (test__start_subtest("preserve_elems")) {
		test_one_map(skel->maps.array_1, skel->progs.read_array_1, false);
		test_one_map(skel->maps.array_2, skel->progs.read_array_2, true);
	}
	if (test__start_subtest("legacy_read"))
		test_legacy_read(skel->maps.array_3, skel->progs.read_array_1_legacy);
	if (test__start_subtest("prog_read_value"))
		test_prog_read_value(skel);

	test_perf_event_helpers__destroy(skel);
}
