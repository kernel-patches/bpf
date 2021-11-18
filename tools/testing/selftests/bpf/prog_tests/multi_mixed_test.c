// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "multi_mixed_test.skel.h"

void test_multi_mixed_test(void)
{
	DECLARE_LIBBPF_OPTS(bpf_link_update_opts, link_upd_opts);
	struct multi_mixed_test *skel = NULL;
	__u32 duration = 0, retval;
	int err, prog_fd;

	skel = multi_mixed_test__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fentry_multi_skel_load"))
		goto cleanup;

	err = multi_mixed_test__attach(skel);
	if (!ASSERT_OK(err, "fentry_attach"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.test1);
	err = bpf_prog_test_run(prog_fd, 1, NULL, 0,
				NULL, NULL, &retval, &duration);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(retval, 0, "test_run");

	ASSERT_EQ(skel->bss->test1_result, 1, "test1_result");
	ASSERT_EQ(skel->bss->test2_result, 1, "test2_result");
	ASSERT_EQ(skel->bss->test3_arg_result, 8, "test3_arg_result");
	ASSERT_EQ(skel->bss->test4_arg_result, 8, "test4_arg_result");
	ASSERT_EQ(skel->bss->test4_ret_result, 8, "test4_ret_result");

cleanup:
	multi_mixed_test__destroy(skel);
}
