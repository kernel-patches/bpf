// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>

#include "test_queue_stack_nested_map.skel.h"


static void test_map_queue_stack_nesting_success(bool is_map_queue)
{
	struct test_queue_stack_nested_map *skel;
	int err;
	int prog_fd;

	LIBBPF_OPTS(bpf_test_run_opts, ropts);

	skel = test_queue_stack_nested_map__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_queue_stack_nested_map__open_and_load"))
		goto out;

	err = test_queue_stack_nested_map__attach(skel);
	if (!ASSERT_OK(err, "test_queue_stack_nested_map__attach"))
		goto out;

	if (is_map_queue) {
		prog_fd = bpf_program__fd(skel->progs.test_queue_nesting);
		err = bpf_prog_test_run_opts(prog_fd, &ropts);
		ASSERT_OK(err, "test_nested_queue_map_run");
	} else {
		prog_fd = bpf_program__fd(skel->progs.test_stack_nesting);
		err = bpf_prog_test_run_opts(prog_fd, &ropts);
		ASSERT_OK(err, "test_nested_stack_map_run");
	}



out:
	test_queue_stack_nested_map__destroy(skel);
}

void test_test_queue_stack_nested_map(void)
{
	if (test__start_subtest("map_queue_nesting"))
		test_map_queue_stack_nesting_success(true);
	if (test__start_subtest("map_stack_nesting"))
		test_map_queue_stack_nesting_success(false);

}

