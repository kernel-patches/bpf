// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */

#include <test_progs.h>
#include <network_helpers.h>

#include "local_kptr_stash.skel.h"
static void test_local_kptr_stash_simple(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		    .data_in = &pkt_v4,
		    .data_size_in = sizeof(pkt_v4),
		    .repeat = 1,
	);
	struct local_kptr_stash *skel;
	int ret;

	skel = local_kptr_stash__open_and_load();
	if (!ASSERT_OK_PTR(skel, "local_kptr_stash__open_and_load"))
		return;

	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.stash_rb_node), &opts);
	ASSERT_OK(ret, "local_kptr_stash_add_nodes run");
	ASSERT_OK(opts.retval, "local_kptr_stash_add_nodes retval");

	local_kptr_stash__destroy(skel);
}

void test_local_kptr_stash_success(void)
{
	if (test__start_subtest("rbtree_add_nodes"))
		test_local_kptr_stash_simple();
}
