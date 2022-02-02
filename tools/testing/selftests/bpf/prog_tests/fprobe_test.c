// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "fprobe.skel.h"
#include "trace_helpers.h"

static void test_skel_api(void)
{
	struct fprobe *skel = NULL;
	__u32 duration = 0, retval;
	int err, prog_fd;

	skel = fprobe__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fprobe__open_and_load"))
		goto cleanup;

	err = fprobe__attach(skel);
	if (!ASSERT_OK(err, "fprobe__attach"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.test1);
	err = bpf_prog_test_run(prog_fd, 1, NULL, 0,
				NULL, NULL, &retval, &duration);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(retval, 0, "test_run");

	ASSERT_EQ(skel->bss->test2_result, 8, "test2_result");
	ASSERT_EQ(skel->bss->test3_result, 8, "test3_result");

cleanup:
	fprobe__destroy(skel);
}

static void test_link_api(struct bpf_link_create_opts *opts)
{
	int err, prog_fd, link1_fd = -1, link2_fd = -1;
	struct fprobe *skel = NULL;
	__u32 duration = 0, retval;

	skel = fprobe__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fentry_raw_skel_load"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.test2);
	link1_fd = bpf_link_create(prog_fd, 0, BPF_TRACE_FPROBE, opts);
	if (!ASSERT_GE(link1_fd, 0, "link_fd"))
		goto cleanup;

	opts->fprobe.flags = BPF_F_FPROBE_RETURN;
	prog_fd = bpf_program__fd(skel->progs.test3);
	link2_fd = bpf_link_create(prog_fd, 0, BPF_TRACE_FPROBE, opts);
	if (!ASSERT_GE(link2_fd, 0, "link_fd"))
		goto cleanup;

	skel->bss->test2_result = 0;
	skel->bss->test3_result = 0;

	prog_fd = bpf_program__fd(skel->progs.test1);
	err = bpf_prog_test_run(prog_fd, 1, NULL, 0,
				NULL, NULL, &retval, &duration);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(retval, 0, "test_run");

	ASSERT_EQ(skel->bss->test2_result, 8, "test2_result");
	ASSERT_EQ(skel->bss->test3_result, 8, "test3_result");

cleanup:
	if (link1_fd != -1)
		close(link1_fd);
	if (link2_fd != -1)
		close(link2_fd);
	fprobe__destroy(skel);
}

static void test_link_api_addrs(void)
{
	DECLARE_LIBBPF_OPTS(bpf_link_create_opts, opts);
	__u64 addrs[8];

	kallsyms_find("bpf_fentry_test1", &addrs[0]);
	kallsyms_find("bpf_fentry_test2", &addrs[1]);
	kallsyms_find("bpf_fentry_test3", &addrs[2]);
	kallsyms_find("bpf_fentry_test4", &addrs[3]);
	kallsyms_find("bpf_fentry_test5", &addrs[4]);
	kallsyms_find("bpf_fentry_test6", &addrs[5]);
	kallsyms_find("bpf_fentry_test7", &addrs[6]);
	kallsyms_find("bpf_fentry_test8", &addrs[7]);

	opts.fprobe.addrs = (__u64) addrs;
	opts.fprobe.cnt = 8;
	test_link_api(&opts);
}

static void test_link_api_syms(void)
{
	DECLARE_LIBBPF_OPTS(bpf_link_create_opts, opts);
	const char *syms[8] = {
		"bpf_fentry_test1",
		"bpf_fentry_test2",
		"bpf_fentry_test3",
		"bpf_fentry_test4",
		"bpf_fentry_test5",
		"bpf_fentry_test6",
		"bpf_fentry_test7",
		"bpf_fentry_test8",
	};

	opts.fprobe.syms = (__u64) syms;
	opts.fprobe.cnt = 8;
	test_link_api(&opts);
}

void test_fprobe_test(void)
{
	test_skel_api();
	test_link_api_syms();
	test_link_api_addrs();
}
