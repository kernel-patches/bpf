// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>

#include "struct_ops_nullable.skel.h"
#include "struct_ops_nullable_fail.skel.h"

/*
 * Attach a callback that gets a trusted and a trusted __nullable task pointer
 * through its argument struct and drive it through the
 * bpf_testmod_ops3_call_test_nullable() kfunc.
 */
static void nullable_member(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct struct_ops_nullable *skel;
	struct bpf_link *link;
	int err;

	skel = struct_ops_nullable__open_and_load();
	if (!ASSERT_OK_PTR(skel, "struct_ops_nullable__open_and_load"))
		return;

	link = bpf_map__attach_struct_ops(skel->maps.testmod_nullable);
	if (!ASSERT_OK_PTR(link, "attach_struct_ops"))
		goto out;

	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.trigger), &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, 0, "trigger_retval");

	bpf_link__destroy(link);
out:
	struct_ops_nullable__destroy(skel);
}

/* Serialized because it attaches the singleton bpf_testmod_ops3. */
void serial_test_struct_ops_nullable(void)
{
	if (test__start_subtest("nullable_member"))
		nullable_member();
	RUN_TESTS(struct_ops_nullable_fail);
}
