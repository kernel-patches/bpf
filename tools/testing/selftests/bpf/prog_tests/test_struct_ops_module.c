// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>

#include "struct_ops_module.skel.h"
#include "testing_helpers.h"

static void test_regular_load()
{
	struct struct_ops_module *skel;
	struct bpf_link *link;
	extern int turnon_kk;
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
	int err;

	turnon_kk = true;
	opts.btf_custom_path = "/sys/kernel/btf/bpf_testmod",

#if 0
	unload_bpf_testmod(true);
	if (!ASSERT_OK(load_bpf_testmod(true), "load_bpf_testmod"))
		return;
#endif

	printf("test_regular_load\n");
	skel = struct_ops_module__open_opts(&opts);
	if (!ASSERT_OK_PTR(skel, "struct_ops_module_open"))
		return;
	err = struct_ops_module__load(skel);
	if (!ASSERT_OK(err, "struct_ops_module_load"))
		return;

	link = bpf_map__attach_struct_ops(skel->maps.testmod_1);
	ASSERT_OK_PTR(link, "attach_test_mod_1");
	bpf_link__destroy(link);

	struct_ops_module__destroy(skel);

#if 0
	unload_bpf_testmod(false);
#endif
}

void serial_test_struct_ops_module(void)
{
	if (test__start_subtest("regular_load"))
		test_regular_load();
}

