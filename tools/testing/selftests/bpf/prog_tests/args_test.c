// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "args_test.skel.h"

void test_args_test(void)
{
	struct args_test *skel = NULL;
	__u32 duration = 0, retval;
	int err, prog_fd;

	skel = args_test__open();
	if (!ASSERT_OK_PTR(skel, "args_test__open"))
		return;

	err = args_test__load(skel);
	if (!ASSERT_OK(err, "args_test__load"))
		goto cleanup;

	err = args_test__attach(skel);
	if (!ASSERT_OK(err, "args_test__attach"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.test1);
	err = bpf_prog_test_run(prog_fd, 1, NULL, 0,
				NULL, NULL, &retval, &duration);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(retval, 0, "test_run");

	ASSERT_EQ(skel->bss->test1_result, 1, "test1_result");
	ASSERT_EQ(skel->bss->test2_result, 1, "test2_result");

cleanup:
	args_test__destroy(skel);
}
