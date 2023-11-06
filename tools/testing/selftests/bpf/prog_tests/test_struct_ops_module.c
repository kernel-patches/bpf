// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>
#include <time.h>

#include "rcu_tasks_trace_gp.skel.h"
#include "struct_ops_module.skel.h"
#include "testmod_btf.skel.h"

static void test_regular_load(void)
{
	struct struct_ops_module *skel;
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
	struct bpf_link *link;
	int err;

	skel = struct_ops_module__open_opts(&opts);
	if (!ASSERT_OK_PTR(skel, "struct_ops_module_open"))
		return;
	err = struct_ops_module__load(skel);
	if (!ASSERT_OK(err, "struct_ops_module_load"))
		goto cleanup;

	link = bpf_map__attach_struct_ops(skel->maps.testmod_1);
	ASSERT_OK_PTR(link, "attach_test_mod_1");

	/* test_2() will be called from bpf_dummy_reg() in bpf_testmod.c */
	ASSERT_EQ(skel->bss->test_2_result, 7, "test_2_result");

	bpf_link__destroy(link);

cleanup:
	struct_ops_module__destroy(skel);
}

static void test_load_without_module(void)
{
	struct struct_ops_module *skel = NULL;
	struct testmod_btf *skel_btf;
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
	struct bpf_link *link_btf = NULL;;
	int err, i;

	skel_btf = testmod_btf__open_and_load();
	if (!ASSERT_OK_PTR(skel_btf, "testmod_btf_open"))
		return;

	link_btf = bpf_program__attach(skel_btf->progs.kprobe_btf_put);
	if (!ASSERT_OK_PTR(link_btf, "kprobe_btf_put_attach"))
		goto cleanup;

	err = unload_bpf_testmod(false);
	if (!ASSERT_OK(err, "unload_bpf_testmod"))
		goto cleanup;

	skel = struct_ops_module__open_opts(&opts);
	if (!ASSERT_OK_PTR(skel, "struct_ops_module_open"))
		goto cleanup;
	err = struct_ops_module__load(skel);
	ASSERT_ERR(err, "struct_ops_module_load");

	/* Wait for the struct_ops map to be freed. Struct_ops maps hold a
	 * refcount to the module btf. And, this function unloads and then
	 * loads bpf_testmod. Without waiting the map to be freed, the next
	 * test may fail since libbpf may use the old btf that is still
	 * alive instead of the new one that is created for the newly
	 * loaded module.
	 */
	for (i = 0; i < 10; i++) {
		if (skel_btf->bss->bpf_testmod_put)
			break;
		usleep(100000);
	}
	ASSERT_EQ(skel_btf->bss->bpf_testmod_put, 1, "btf_put");

cleanup:
	bpf_link__destroy(link_btf);
	struct_ops_module__destroy(skel);
	testmod_btf__destroy(skel_btf);
	/* Without this, the next test may fail */
	load_bpf_testmod(false);
}

static void test_attach_without_module(void)
{
	struct struct_ops_module *skel = NULL;
	struct testmod_btf *skel_btf;
	struct bpf_link *link, *link_btf = NULL;
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
	int err, i;

	skel_btf = testmod_btf__open_and_load();
	if (!ASSERT_OK_PTR(skel_btf, "testmod_btf_open"))
		return;

	link_btf = bpf_program__attach(skel_btf->progs.kprobe_btf_put);
	if (!ASSERT_OK_PTR(link_btf, "kprobe_btf_put_attach"))
		goto cleanup;

	skel = struct_ops_module__open_opts(&opts);
	if (!ASSERT_OK_PTR(skel, "struct_ops_module_open"))
		goto cleanup;
	err = struct_ops_module__load(skel);
	if (!ASSERT_OK(err, "struct_ops_module_load"))
		goto cleanup;

	err = unload_bpf_testmod(false);
	if (!ASSERT_OK(err, "unload_bpf_testmod"))
		goto cleanup;

	link = bpf_map__attach_struct_ops(skel->maps.testmod_1);
	ASSERT_ERR_PTR(link, "attach_test_mod_1");

	struct_ops_module__destroy(skel);
	skel = NULL;

	/* Wait for the struct_ops map to be freed */
	for (i = 0; i < 10; i++) {
		if (skel_btf->bss->bpf_testmod_put)
			break;
		usleep(100000);
	}
	ASSERT_EQ(skel_btf->bss->bpf_testmod_put, 1, "btf_put");

cleanup:
	bpf_link__destroy(link_btf);
	struct_ops_module__destroy(skel);
	testmod_btf__destroy(skel_btf);
	/* Without this, the next test may fail */
	load_bpf_testmod(false);
}

void serial_test_struct_ops_module(void)
{
	if (test__start_subtest("regular_load"))
		test_regular_load();

	if (test__start_subtest("load_without_module"))
		test_load_without_module();

	if (test__start_subtest("attach_without_module"))
		test_attach_without_module();
}

