// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "fentry_fexit_multi_test.skel.h"

void test_fentry_fexit_multi_test(void)
{
	DECLARE_LIBBPF_OPTS(bpf_link_update_opts, link_upd_opts);
	struct fentry_fexit_multi_test *skel = NULL;
	unsigned long long *bpf_fentry_test;
	__u32 duration = 0, retval;
	struct bpf_link *link;
	int err, prog_fd;

	skel = fentry_fexit_multi_test__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fentry_multi_skel_load"))
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

	link = bpf_program__attach(skel->progs.test1);
	if (!ASSERT_OK_PTR(link, "attach_fentry_fexit"))
		goto cleanup;

	err = bpf_link_update(bpf_link__fd(link),
			      bpf_program__fd(skel->progs.test2),
			      NULL);
	if (!ASSERT_OK(err, "bpf_link_update"))
		goto cleanup_link;

	prog_fd = bpf_program__fd(skel->progs.test1);
	err = bpf_prog_test_run(prog_fd, 1, NULL, 0,
				NULL, NULL, &retval, &duration);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(retval, 0, "test_run");

	ASSERT_EQ(skel->bss->test1_arg_result, 8, "test1_arg_result");
	ASSERT_EQ(skel->bss->test2_arg_result, 8, "test2_arg_result");
	ASSERT_EQ(skel->bss->test2_ret_result, 8, "test2_ret_result");

cleanup_link:
	bpf_link__destroy(link);
cleanup:
	fentry_fexit_multi_test__destroy(skel);
}
