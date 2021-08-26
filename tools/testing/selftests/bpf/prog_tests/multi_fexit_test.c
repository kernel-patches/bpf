// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "multi_fexit_test.skel.h"
#include "trace_helpers.h"

void test_multi_fexit_test(void)
{
	struct multi_fexit_test *skel = NULL;
	__u32 duration = 0, retval;
	int err, prog_fd;

	skel = multi_fexit_test__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fexit_multi_skel_load"))
		goto cleanup;

	err = multi_fexit_test__attach(skel);
	if (!ASSERT_OK(err, "fexit_attach"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.test);
	err = bpf_prog_test_run(prog_fd, 1, NULL, 0,
				NULL, NULL, &retval, &duration);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(retval, 0, "test_run");

	ASSERT_EQ(skel->bss->test_arg_result, 8, "fexit_multi_arg_result");
	ASSERT_EQ(skel->bss->test_ret_result, 8, "fexit_multi_ret_result");

cleanup:
	multi_fexit_test__destroy(skel);
}
