// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>
#include <string.h>
#include <stdio.h>
#include "rhash.skel.h"
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>

static void rhash_run(const char *prog_name)
{
	struct rhash *skel;
	struct bpf_program *prog;
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err;

	skel = rhash__open();
	if (!ASSERT_OK_PTR(skel, "rhash__open"))
		return;

	prog = bpf_object__find_program_by_name(skel->obj, prog_name);
	if (!ASSERT_OK_PTR(prog, "bpf_object__find_program_by_name"))
		goto cleanup;
	bpf_program__set_autoload(prog, true);

	err = rhash__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto cleanup;

	err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);
	if (!ASSERT_OK(err, "prog run"))
		goto cleanup;

	if (!ASSERT_OK(skel->bss->err, "bss->err"))
		goto cleanup;

cleanup:
	rhash__destroy(skel);
}

void test_rhash(void)
{
	if (test__start_subtest("test_rhash_lookup_update"))
		rhash_run("test_rhash_lookup_update");

	if (test__start_subtest("test_rhash_update_delete"))
		rhash_run("test_rhash_update_delete");

	if (test__start_subtest("test_rhash_update_elements"))
		rhash_run("test_rhash_update_elements");

	if (test__start_subtest("test_rhash_update_exist"))
		rhash_run("test_rhash_update_exist");

	if (test__start_subtest("test_rhash_update_any"))
		rhash_run("test_rhash_update_any");

	if (test__start_subtest("test_rhash_noexist_duplicate"))
		rhash_run("test_rhash_noexist_duplicate");

	if (test__start_subtest("test_rhash_delete_nonexistent"))
		rhash_run("test_rhash_delete_nonexistent");
}
