// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "test_stacktrace_map.skel.h"

static void check_stackmap(int control_map_fd, int stackid_hmap_fd,
			   int stackmap_fd, int stack_amap_fd, int skip)
{
	__u32 key, val, duration = 0;
	int err, stack_trace_len;

	/* disable stack trace collection */
	key = 0;
	val = 1;
	bpf_map_update_elem(control_map_fd, &key, &val, 0);

	/* for every element in stackid_hmap, we can find a corresponding one
	 * in stackmap, and vice versa.
	 */
	err = compare_map_keys(stackid_hmap_fd, stackmap_fd);
	if (CHECK(err, "compare_map_keys stackid_hmap vs. stackmap",
		  "err %d errno %d\n", err, errno))
		return;

	err = compare_map_keys(stackmap_fd, stackid_hmap_fd);
	if (CHECK(err, "compare_map_keys stackmap vs. stackid_hmap",
		  "err %d errno %d\n", err, errno))
		return;

	stack_trace_len = PERF_MAX_STACK_DEPTH * sizeof(__u64);
	err = compare_stack_ips_skip(stackmap_fd, stack_amap_fd, stack_trace_len, skip);
	CHECK(err, "compare_stack_ips stackmap vs. stack_amap",
		"err %d errno %d\n", err, errno);
}

static void test_stacktrace_map_tp(void)
{
	int control_map_fd, stackid_hmap_fd, stackmap_fd, stack_amap_fd;
	const char *prog_name = "oncpu";
	int err, prog_fd;
	const char *file = "./test_stacktrace_map.bpf.o";
	__u32 duration = 0;
	struct bpf_program *prog;
	struct bpf_object *obj;
	struct bpf_link *link;

	err = bpf_prog_test_load(file, BPF_PROG_TYPE_TRACEPOINT, &obj, &prog_fd);
	if (CHECK(err, "prog_load", "err %d errno %d\n", err, errno))
		return;

	prog = bpf_object__find_program_by_name(obj, prog_name);
	if (CHECK(!prog, "find_prog", "prog '%s' not found\n", prog_name))
		goto close_prog;

	link = bpf_program__attach_tracepoint(prog, "sched", "sched_switch");
	if (!ASSERT_OK_PTR(link, "attach_tp"))
		goto close_prog;

	/* find map fds */
	control_map_fd = bpf_find_map(__func__, obj, "control_map");
	if (CHECK_FAIL(control_map_fd < 0))
		goto disable_pmu;

	stackid_hmap_fd = bpf_find_map(__func__, obj, "stackid_hmap");
	if (CHECK_FAIL(stackid_hmap_fd < 0))
		goto disable_pmu;

	stackmap_fd = bpf_find_map(__func__, obj, "stackmap");
	if (CHECK_FAIL(stackmap_fd < 0))
		goto disable_pmu;

	stack_amap_fd = bpf_find_map(__func__, obj, "stack_amap");
	if (CHECK_FAIL(stack_amap_fd < 0))
		goto disable_pmu;

	/* give some time for bpf program run */
	sleep(1);

	check_stackmap(control_map_fd, stackid_hmap_fd, stackmap_fd, stack_amap_fd, 0);

disable_pmu:
	bpf_link__destroy(link);
close_prog:
	bpf_object__close(obj);
}

static void test_stacktrace_map_kprobe_multi(void)
{
	int control_map_fd, stackid_hmap_fd, stackmap_fd, stack_amap_fd;
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct test_stacktrace_map *skel;
	struct bpf_link *link;
	int prog_fd, err;

	skel = test_stacktrace_map__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_stacktrace_map__open_and_load"))
		return;

	link = bpf_program__attach_kprobe_multi_opts(skel->progs.kprobe,
						     "bpf_fentry_test1", NULL);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_kprobe_multi_opts"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.trigger);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, 0, "test_run");

	control_map_fd = bpf_map__fd(skel->maps.control_map);
	stackid_hmap_fd = bpf_map__fd(skel->maps.stackid_hmap);
	stackmap_fd = bpf_map__fd(skel->maps.stackmap);
	stack_amap_fd = bpf_map__fd(skel->maps.stack_amap);

	check_stackmap(control_map_fd, stackid_hmap_fd, stackmap_fd, stack_amap_fd, 0);

cleanup:
	test_stacktrace_map__destroy(skel);
}

static void test_stacktrace_map_fentry(void)
{
	int control_map_fd, stackid_hmap_fd, stackmap_fd, stack_amap_fd;
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct test_stacktrace_map *skel;
	struct bpf_link *link;
	int prog_fd, err;

	skel = test_stacktrace_map__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_stacktrace_map__open_and_load"))
		return;

	link = bpf_program__attach_trace(skel->progs.fentry);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_trace"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.trigger);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, 0, "test_run");

	control_map_fd = bpf_map__fd(skel->maps.control_map);
	stackid_hmap_fd = bpf_map__fd(skel->maps.stackid_hmap);
	stackmap_fd = bpf_map__fd(skel->maps.stackmap);
	stack_amap_fd = bpf_map__fd(skel->maps.stack_amap);

	check_stackmap(control_map_fd, stackid_hmap_fd, stackmap_fd, stack_amap_fd, 2);

	getchar();

cleanup:
	test_stacktrace_map__destroy(skel);
}

void test_stacktrace_map(void)
{
	if (test__start_subtest("tp"))
		test_stacktrace_map_tp();
	if (test__start_subtest("kprobe_multi"))
		test_stacktrace_map_kprobe_multi();
	if (test__start_subtest("fentry"))
		test_stacktrace_map_fentry();
}
