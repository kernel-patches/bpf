// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "kprobe_multi.skel.h"
#include "trace_helpers.h"

static void test_skel_api(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct kprobe_multi *skel = NULL;
	int err, prog_fd;

	skel = kprobe_multi__open_and_load();
	if (!ASSERT_OK_PTR(skel, "kprobe_multi__open_and_load"))
		goto cleanup;

	err = kprobe_multi__attach(skel);
	if (!ASSERT_OK(err, "kprobe_multi__attach"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.test1);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, 0, "test_run");

	ASSERT_EQ(skel->bss->test2_result, 8, "test2_result");
	ASSERT_EQ(skel->bss->test3_result, 8, "test3_result");

cleanup:
	kprobe_multi__destroy(skel);
}

static void test_link_api(struct bpf_link_create_opts *opts)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	int err, prog_fd, link1_fd = -1, link2_fd = -1;
	struct kprobe_multi *skel = NULL;

	skel = kprobe_multi__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fentry_raw_skel_load"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.test2);
	link1_fd = bpf_link_create(prog_fd, 0, BPF_TRACE_KPROBE_MULTI, opts);
	if (!ASSERT_GE(link1_fd, 0, "link_fd"))
		goto cleanup;

	opts->kprobe_multi.flags = BPF_F_KPROBE_MULTI_RETURN;
	prog_fd = bpf_program__fd(skel->progs.test3);
	link2_fd = bpf_link_create(prog_fd, 0, BPF_TRACE_KPROBE_MULTI, opts);
	if (!ASSERT_GE(link2_fd, 0, "link_fd"))
		goto cleanup;

	skel->bss->test2_result = 0;
	skel->bss->test3_result = 0;

	prog_fd = bpf_program__fd(skel->progs.test1);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, 0, "test_run");

	ASSERT_EQ(skel->bss->test2_result, 8, "test2_result");
	ASSERT_EQ(skel->bss->test3_result, 8, "test3_result");

cleanup:
	if (link1_fd != -1)
		close(link1_fd);
	if (link2_fd != -1)
		close(link2_fd);
	kprobe_multi__destroy(skel);
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

	opts.kprobe_multi.addrs = (__u64) addrs;
	opts.kprobe_multi.cnt = 8;
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

	opts.kprobe_multi.syms = (__u64) syms;
	opts.kprobe_multi.cnt = 8;
	test_link_api(&opts);
}

void test_kprobe_multi_test(void)
{
	test_skel_api();
	test_link_api_syms();
	test_link_api_addrs();
}
