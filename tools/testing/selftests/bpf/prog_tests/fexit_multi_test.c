// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "fexit_multi_test.skel.h"
#include "trace_helpers.h"

void test_fexit_multi_test(void)
{
	struct fexit_multi_test *skel = NULL;
	unsigned long long *bpf_fentry_test;
	__u32 duration = 0, retval;
	int err, prog_fd;

	skel = fexit_multi_test__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fexit_multi_skel_load"))
		goto cleanup;

	bpf_fentry_test = &skel->bss->bpf_fentry_test[0];
	ASSERT_OK(kallsyms_find("bpf_fentry_test1", &bpf_fentry_test[0]), "kallsyms_find");
	ASSERT_OK(kallsyms_find("bpf_fentry_test2", &bpf_fentry_test[1]), "kallsyms_find");
	ASSERT_OK(kallsyms_find("bpf_fentry_test3", &bpf_fentry_test[2]), "kallsyms_find");
	ASSERT_OK(kallsyms_find("bpf_fentry_test4", &bpf_fentry_test[3]), "kallsyms_find");
	ASSERT_OK(kallsyms_find("bpf_fentry_test5", &bpf_fentry_test[4]), "kallsyms_find");
	ASSERT_OK(kallsyms_find("bpf_fentry_test6", &bpf_fentry_test[5]), "kallsyms_find");
	ASSERT_OK(kallsyms_find("bpf_fentry_test7", &bpf_fentry_test[6]), "kallsyms_find");
	ASSERT_OK(kallsyms_find("bpf_fentry_test8", &bpf_fentry_test[7]), "kallsyms_find");

	err = fexit_multi_test__attach(skel);
	if (!ASSERT_OK(err, "fexit_attach"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.test);
	err = bpf_prog_test_run(prog_fd, 1, NULL, 0,
				NULL, NULL, &retval, &duration);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(retval, 0, "test_run");

	ASSERT_EQ(skel->bss->test_arg_result, 8, "fexit_multi_arg_result");
	ASSERT_EQ(skel->bss->test_ret_result, 8, "fexit_multi_ret_result");

	fexit_multi_test__detach(skel);

cleanup:
	fexit_multi_test__destroy(skel);
}
