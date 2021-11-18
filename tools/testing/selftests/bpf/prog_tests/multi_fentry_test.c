// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "multi_fentry_test.skel.h"
#include "trace_helpers.h"

void test_multi_fentry_test(void)
{
	struct multi_fentry_test *skel = NULL;
	__u32 duration = 0, retval;
	int err, prog_fd;

	skel = multi_fentry_test__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fentry_multi_skel_load"))
		goto cleanup;

	err = multi_fentry_test__attach(skel);
	if (!ASSERT_OK(err, "fentry_attach"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.test);
	err = bpf_prog_test_run(prog_fd, 1, NULL, 0,
				NULL, NULL, &retval, &duration);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(retval, 0, "test_run");

	ASSERT_EQ(skel->bss->test_result, 8, "test_result");

cleanup:
	multi_fentry_test__destroy(skel);
}
