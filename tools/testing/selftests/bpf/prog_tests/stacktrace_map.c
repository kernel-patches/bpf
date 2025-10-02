// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "stacktrace_map.skel.h"

static void check_stackmap(struct stacktrace_map *skel)
{
	int control_map_fd, stackid_hmap_fd, stackmap_fd, stack_amap_fd;
	int err, stack_trace_len;
	__u32 key, val, stack_id, duration = 0;
	__u64 stack[PERF_MAX_STACK_DEPTH];

	control_map_fd = bpf_map__fd(skel->maps.control_map);
	stackid_hmap_fd = bpf_map__fd(skel->maps.stackid_hmap);
	stackmap_fd = bpf_map__fd(skel->maps.stackmap);
	stack_amap_fd = bpf_map__fd(skel->maps.stack_amap);

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
	err = compare_stack_ips(stackmap_fd, stack_amap_fd, stack_trace_len);
	if (CHECK(err, "compare_stack_ips stackmap vs. stack_amap",
		  "err %d errno %d\n", err, errno))
		return;

	stack_id = skel->bss->stack_id;
	err = bpf_map_lookup_and_delete_elem(stackmap_fd, &stack_id,  stack);
	if (!ASSERT_OK(err, "lookup and delete target stack_id"))
		return;

	err = bpf_map_lookup_elem(stackmap_fd, &stack_id, stack);
	ASSERT_EQ(err, -ENOENT, "lookup deleted stack_id");
}

static void test_stacktrace_map_tp(bool raw_tp)
{
	struct stacktrace_map *skel;

	skel = stacktrace_map__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	if (raw_tp) {
		skel->links.tp = bpf_program__attach_raw_tracepoint(skel->progs.raw_tp, "sched_switch");
	} else {
		skel->links.tp = bpf_program__attach_tracepoint(skel->progs.tp, "sched", "sched_switch");
	}

	if (!ASSERT_OK_PTR(skel->links.tp, "attach"))
		goto out;

	/* give some time for bpf program run */
	sleep(1);

	check_stackmap(skel);

out:
	stacktrace_map__destroy(skel);
}

static void test_stacktrace_map_kprobe(bool retprobe)
{
	LIBBPF_OPTS(bpf_kprobe_opts, opts,
		.retprobe = retprobe
	);
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct stacktrace_map *skel;
	int prog_fd, err;

	skel = stacktrace_map__open_and_load();
	if (!ASSERT_OK_PTR(skel, "stacktrace_map__open_and_load"))
		return;

	skel->links.kprobe_test = bpf_program__attach_kprobe_opts(skel->progs.kprobe_test,
					       "bpf_fentry_test1", &opts);
	if (!ASSERT_OK_PTR(skel->links.kprobe_test, "bpf_program__attach_kprobe_opts"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.trigger);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, 0, "test_run");

	check_stackmap(skel);

cleanup:
	stacktrace_map__destroy(skel);
}

static void test_stacktrace_map_kprobe_multi(bool retprobe)
{
	LIBBPF_OPTS(bpf_kprobe_multi_opts, opts,
		.retprobe = retprobe
	);
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct stacktrace_map *skel;
	int prog_fd, err;

	skel = stacktrace_map__open_and_load();
	if (!ASSERT_OK_PTR(skel, "stacktrace_map__open_and_load"))
		return;

	if (retprobe && skel->kconfig->CONFIG_UNWINDER_ORC) {
		test__skip();
		goto cleanup;
	}

	skel->links.kprobe_multi_test = bpf_program__attach_kprobe_multi_opts(skel->progs.kprobe_multi_test,
						     "bpf_fentry_test1", &opts);
	if (!ASSERT_OK_PTR(skel->links.kprobe_multi_test, "bpf_program__attach_kprobe_multi_opts"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.trigger);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, 0, "test_run");

	check_stackmap(skel);

cleanup:
	stacktrace_map__destroy(skel);
}

static void test_stacktrace_map_tracing(bool exit)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct stacktrace_map *skel;
	struct bpf_program *prog;
	int prog_fd, err;

	skel = stacktrace_map__open_and_load();
	if (!ASSERT_OK_PTR(skel, "stacktrace_map__open_and_load"))
		return;

	prog = exit ? skel->progs.fexit : skel->progs.fentry;

	skel->links.fentry = bpf_program__attach_trace(prog);
	if (!ASSERT_OK_PTR(skel->links.fentry, "bpf_program__attach_trace"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.trigger);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, 0, "test_run");

	check_stackmap(skel);

cleanup:
	stacktrace_map__destroy(skel);
}

noinline void stacktrace_map_uprobe_trigger(void)
{
        asm volatile ("");
}

static void test_stacktrace_map_uprobe(bool retprobe)
{
	LIBBPF_OPTS(bpf_uprobe_opts, opts,
		.retprobe  = retprobe,
		.func_name = "stacktrace_map_uprobe_trigger",
	);
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct stacktrace_map *skel;

	skel = stacktrace_map__open_and_load();
	if (!ASSERT_OK_PTR(skel, "stacktrace_map__open_and_load"))
		return;

	skel->links.uprobe_test = bpf_program__attach_uprobe_opts(skel->progs.uprobe_test,
					       -1 /* pid */, "/proc/self/exe", 0 /* offset */,
					       &opts);
	if (!ASSERT_OK_PTR(skel->links.uprobe_test, "bpf_program__attach_uprobe_opts"))
		goto cleanup;

	stacktrace_map_uprobe_trigger();
	check_stackmap(skel);

cleanup:
	stacktrace_map__destroy(skel);
}

static void test_stacktrace_map_uprobe_multi(bool retprobe)
{
	LIBBPF_OPTS(bpf_uprobe_multi_opts, opts,
		.retprobe = retprobe
	);
	struct stacktrace_map *skel;

	skel = stacktrace_map__open_and_load();
	if (!ASSERT_OK_PTR(skel, "stacktrace_map__open_and_load"))
		return;

	skel->links.uprobe_multi_test = bpf_program__attach_uprobe_multi(skel->progs.uprobe_multi_test,
						-1 /* pid */, "/proc/self/exe",
						"stacktrace_map_uprobe_trigger",
						&opts);
	if (!ASSERT_OK_PTR(skel->links.uprobe_multi_test, "bpf_program__attach_uprobe_multi"))
		goto cleanup;

	stacktrace_map_uprobe_trigger();
	check_stackmap(skel);

cleanup:
	stacktrace_map__destroy(skel);
}

void test_stacktrace_map(void)
{
	if (test__start_subtest("tp"))
		test_stacktrace_map_tp(false);
	if (test__start_subtest("raw_tp"))
		test_stacktrace_map_tp(true);
	if (test__start_subtest("kprobe"))
		test_stacktrace_map_kprobe(false);
	if (test__start_subtest("kretprobe"))
		test_stacktrace_map_kprobe(true);
	if (test__start_subtest("kprobe_multi"))
		test_stacktrace_map_kprobe_multi(false);
	if (test__start_subtest("kretprobe_multi"))
		test_stacktrace_map_kprobe_multi(true);
	if (test__start_subtest("fentry"))
		test_stacktrace_map_tracing(false);
	if (test__start_subtest("fexit"))
		test_stacktrace_map_tracing(true);
	if (test__start_subtest("uprobe"))
		test_stacktrace_map_uprobe(false);
	if (test__start_subtest("uretprobe"))
		test_stacktrace_map_uprobe(true);
	if (test__start_subtest("uprobe_multi"))
		test_stacktrace_map_uprobe_multi(false);
	if (test__start_subtest("uretprobe_multi"))
		test_stacktrace_map_uprobe_multi(true);
}
