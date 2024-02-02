// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>
#include <time.h>

#include "struct_ops_maybe_null.skel.h"
#include "struct_ops_maybe_null_fail.skel.h"

/* Test that the verifier accepts a program that access a nullable pointer
 * with a proper check.
 */
static void maybe_null(void)
{
	struct struct_ops_maybe_null *skel;

	skel = struct_ops_maybe_null__open_and_load();
	if (!ASSERT_OK_PTR(skel, "struct_ops_module_open_and_load"))
		return;

	struct_ops_maybe_null__destroy(skel);
}

/* Test that the verifier rejects a program that access a nullable pointer
 * without a check beforehand.
 */
static void maybe_null_fail(void)
{
	struct bpf_link *link_1 = NULL, *link_2 = NULL,
		*link_3 = NULL, *link_4 = NULL;
	struct struct_ops_maybe_null_fail *skel;

	skel = struct_ops_maybe_null_fail__open();
	if (!ASSERT_OK_PTR(skel, "struct_ops_module_fail__open"))
		return;

	link_1 = bpf_map__attach_struct_ops(skel->maps.testmod_struct_ptr);
	ASSERT_ERR_PTR(link_1, "bpf_map__attach_struct_ops struct_ptr");

	link_2 = bpf_map__attach_struct_ops(skel->maps.testmod_scalar_ptr);
	ASSERT_ERR_PTR(link_2, "bpf_map__attach_struct_ops scalar_ptr");

	link_3 = bpf_map__attach_struct_ops(skel->maps.testmod_array_ptr);
	ASSERT_ERR_PTR(link_3, "bpf_map__attach_struct_ops array_ptr");

	link_4 = bpf_map__attach_struct_ops(skel->maps.testmod_var_array_ptr);
	ASSERT_ERR_PTR(link_4, "bpf_map__attach_struct_ops var_array_ptr");

	bpf_link__destroy(link_1);
	bpf_link__destroy(link_2);
	bpf_link__destroy(link_3);
	bpf_link__destroy(link_4);
	struct_ops_maybe_null_fail__destroy(skel);
}

void test_struct_ops_maybe_null(void)
{
	if (test__start_subtest("maybe_null"))
		maybe_null();
	if (test__start_subtest("maybe_null_fail"))
		maybe_null_fail();
}
