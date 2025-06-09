// SPDX-License-Identifier: GPL-2.0-only

#include <test_progs.h>

#include "struct_ops_this_ptr.skel.h"
#include "struct_ops_this_ptr_in_timer.skel.h"

static void test_struct_ops_this_ptr_in_timer_common(int timer_nsec, int expected_data)
{
	struct struct_ops_this_ptr_in_timer *skel;
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct bpf_link *link;
	int err, prog_fd;

	skel = struct_ops_this_ptr_in_timer__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	skel->bss->timer_nsec = timer_nsec;

	link = bpf_map__attach_struct_ops(skel->maps.testmod_this_ptr);
	if (!ASSERT_OK_PTR(link, "bpf_map__attach_struct_ops"))
		goto out;

	prog_fd = bpf_program__fd(skel->progs.syscall_this_ptr_in_timer);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "bpf_prog_test_run_opts");

	bpf_link__destroy(link);

	/* Check st_ops3_data after timer_cb runs */
	while (!READ_ONCE(skel->bss->st_ops3_data))
		sched_yield();
	ASSERT_EQ(skel->bss->st_ops3_data, expected_data, "st_ops->data");
out:
	struct_ops_this_ptr_in_timer__destroy(skel);
}

static void test_struct_ops_this_ptr_in_timer(void)
{
	/* Run timer callback immediately */
	test_struct_ops_this_ptr_in_timer_common(0, 1234);
}

static void test_struct_ops_this_ptr_in_timer_after_detach(void)
{
	/*
	 * Run timer callback 0.1s after test run. By then the struct_ops map
	 * should have been detached.
	 */
	test_struct_ops_this_ptr_in_timer_common(100000000, -1);
}

void serial_test_struct_ops_this_ptr(void)
{
	RUN_TESTS(struct_ops_this_ptr);
	if (test__start_subtest("struct_ops_this_ptr_in_timer"))
		test_struct_ops_this_ptr_in_timer();
	if (test__start_subtest("struct_ops_this_ptr_in_timer_after_detach"))
		test_struct_ops_this_ptr_in_timer_after_detach();
}
