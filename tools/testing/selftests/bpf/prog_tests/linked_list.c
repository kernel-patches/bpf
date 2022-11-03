// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>

#include "linked_list.skel.h"

static void test_linked_list_success(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 1,
	);
	struct linked_list *skel;
	int key = 0, ret;
	char buf[32];

	skel = linked_list__open_and_load();
	if (!ASSERT_OK_PTR(skel, "linked_list__open_and_load"))
		return;

	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.map_list_push_pop), &opts);
	ASSERT_OK(ret, "map_list_push_pop");
	ASSERT_OK(opts.retval, "map_list_push_pop retval");

	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.global_list_push_pop), &opts);
	ASSERT_OK(ret, "global_list_push_pop");
	ASSERT_OK(opts.retval, "global_list_push_pop retval");

	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.global_list_push_pop_unclean), &opts);
	ASSERT_OK(ret, "global_list_push_pop_unclean");
	ASSERT_OK(opts.retval, "global_list_push_pop_unclean retval");

	ASSERT_OK(bpf_map_update_elem(bpf_map__fd(skel->maps.data_A), &key, buf, 0),
		  "check_and_free_fields");
	ASSERT_OK(bpf_map_update_elem(bpf_map__fd(skel->maps.array_map), &key, buf, 0),
		  "check_and_free_fields");

	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.map_list_push_pop_multiple), &opts);
	ASSERT_OK(ret, "map_list_push_pop_multiple");
	ASSERT_OK(opts.retval, "map_list_push_pop_multiple retval");

	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.global_list_push_pop_multiple), &opts);
	ASSERT_OK(ret, "global_list_push_pop_multiple");
	ASSERT_OK(opts.retval, "global_list_push_pop_multiple retval");

	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.global_list_push_pop_multiple_unclean), &opts);
	ASSERT_OK(ret, "global_list_push_pop_multiple_unclean");
	ASSERT_OK(opts.retval, "global_list_push_pop_multiple_unclean retval");

	ASSERT_OK(bpf_map_update_elem(bpf_map__fd(skel->maps.data_A), &key, buf, 0),
		  "check_and_free_fields");
	ASSERT_OK(bpf_map_update_elem(bpf_map__fd(skel->maps.array_map), &key, buf, 0),
		  "check_and_free_fields");

	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.map_list_in_list), &opts);
	ASSERT_OK(ret, "map_list_in_list");
	ASSERT_OK(opts.retval, "map_list_in_list retval");

	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.global_list_in_list), &opts);
	ASSERT_OK(ret, "global_list_in_list");
	ASSERT_OK(opts.retval, "global_list_in_list retval");

	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.global_list_in_list_unclean), &opts);
	ASSERT_OK(ret, "global_list_in_list_unclean");
	ASSERT_OK(opts.retval, "global_list_in_list_unclean retval");

	ASSERT_OK(bpf_map_update_elem(bpf_map__fd(skel->maps.data_A), &key, buf, 0),
		  "check_and_free_fields");
	ASSERT_OK(bpf_map_update_elem(bpf_map__fd(skel->maps.array_map), &key, buf, 0),
		  "check_and_free_fields");

	linked_list__destroy(skel);
}

void test_linked_list(void)
{
	test_linked_list_success();
}
