// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "multi_kprobe.skel.h"
#include "trace_helpers.h"

static void test_funcs_api(void)
{
	struct multi_kprobe *skel = NULL;
	__u32 duration = 0, retval;
	int err, prog_fd;

	skel = multi_kprobe__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fentry_multi_skel_load"))
		goto cleanup;

	err = multi_kprobe__attach(skel);
	if (!ASSERT_OK(err, "fentry_attach"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.test1);
	err = bpf_prog_test_run(prog_fd, 1, NULL, 0,
				NULL, NULL, &retval, &duration);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(retval, 0, "test_run");

	ASSERT_EQ(skel->bss->test2_result, 8, "test2_result");
	ASSERT_EQ(skel->bss->test3_result, 8, "test3_result");

cleanup:
	multi_kprobe__destroy(skel);
}

static void test_addrs_api(void)
{
	struct bpf_link *link1 = NULL, *link2 = NULL;
	DECLARE_LIBBPF_OPTS(bpf_kprobe_opts, opts);
	struct multi_kprobe *skel = NULL;
	__u32 duration = 0, retval;
	int err, prog_fd;
	__u64 addrs[8];

	skel = multi_kprobe__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fentry_multi_skel_load"))
		goto cleanup;

	kallsyms_find("bpf_fentry_test1", &addrs[0]);
	kallsyms_find("bpf_fentry_test2", &addrs[1]);
	kallsyms_find("bpf_fentry_test3", &addrs[2]);
	kallsyms_find("bpf_fentry_test4", &addrs[3]);
	kallsyms_find("bpf_fentry_test5", &addrs[4]);
	kallsyms_find("bpf_fentry_test6", &addrs[5]);
	kallsyms_find("bpf_fentry_test7", &addrs[6]);
	kallsyms_find("bpf_fentry_test8", &addrs[7]);

	opts.multi.cnt = 8;
	opts.multi.addrs = (__u64 *) &addrs;
	link1 = bpf_program__attach_kprobe_opts(skel->progs.test2, NULL, &opts);
	if (!ASSERT_OK_PTR(link1, "link1"))
		goto cleanup;

	link2 = bpf_program__attach_kprobe_opts(skel->progs.test3, NULL, &opts);
	if (!ASSERT_OK_PTR(link1, "link1"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.test1);
	err = bpf_prog_test_run(prog_fd, 1, NULL, 0,
				NULL, NULL, &retval, &duration);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(retval, 0, "test_run");

	ASSERT_EQ(skel->bss->test2_result, 8, "test2_result");
	ASSERT_EQ(skel->bss->test3_result, 8, "test3_result");

cleanup:
	bpf_link__destroy(link1);
	bpf_link__destroy(link2);
	multi_kprobe__destroy(skel);
}
void test_multi_kprobe_test(void)
{
	test_funcs_api();
	test_addrs_api();
}
