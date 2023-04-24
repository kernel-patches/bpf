// SPDX-License-Identifier: GPL-2.0

#include <unistd.h>
#include <test_progs.h>
#include "uprobe_multi.skel.h"

noinline void uprobe_multi_func_1(void)
{
	asm volatile ("");
}

noinline void uprobe_multi_func_2(void)
{
	asm volatile ("");
}

noinline void uprobe_multi_func_3(void)
{
	asm volatile ("");
}

static void uprobe_multi_test_run(struct uprobe_multi *skel)
{
	skel->bss->uprobe_multi_func_1_addr = (u64) uprobe_multi_func_1;
	skel->bss->uprobe_multi_func_2_addr = (u64) uprobe_multi_func_2;
	skel->bss->uprobe_multi_func_3_addr = (u64) uprobe_multi_func_3;

	skel->bss->pid = getpid();

	uprobe_multi_func_1();
	uprobe_multi_func_2();
	uprobe_multi_func_3();

	ASSERT_EQ(skel->bss->uprobe_multi_func_1_result, 1, "uprobe_multi_func_1_result");
	ASSERT_EQ(skel->bss->uprobe_multi_func_2_result, 1, "uprobe_multi_func_2_result");
	ASSERT_EQ(skel->bss->uprobe_multi_func_3_result, 1, "uprobe_multi_func_3_result");

	ASSERT_EQ(skel->bss->uretprobe_multi_func_1_result, 1, "uretprobe_multi_func_1_result");
	ASSERT_EQ(skel->bss->uretprobe_multi_func_2_result, 1, "uretprobe_multi_func_2_result");
	ASSERT_EQ(skel->bss->uretprobe_multi_func_3_result, 1, "uretprobe_multi_func_3_result");
}

static void test_skel_api(void)
{
	struct uprobe_multi *skel = NULL;
	int err;

	skel = uprobe_multi__open_and_load();
	if (!ASSERT_OK_PTR(skel, "uprobe_multi__open_and_load"))
		goto cleanup;

	err = uprobe_multi__attach(skel);
	if (!ASSERT_OK(err, "uprobe_multi__attach"))
		goto cleanup;

	uprobe_multi_test_run(skel);

cleanup:
	uprobe_multi__destroy(skel);
}

static void
test_attach_api(const char *binary, const char *pattern, struct bpf_uprobe_multi_opts *opts)
{
	struct bpf_link *link1 = NULL, *link2 = NULL;
	struct uprobe_multi *skel = NULL;

	skel = uprobe_multi__open_and_load();
	if (!ASSERT_OK_PTR(skel, "uprobe_multi"))
		goto cleanup;

	link1 = bpf_program__attach_uprobe_multi_opts(skel->progs.test_uprobe,
						      binary, pattern, opts);
	if (!ASSERT_OK_PTR(link1, "bpf_program__attach_uprobe_multi_opts"))
		goto cleanup;

	opts->retprobe = true;
	link2 = bpf_program__attach_uprobe_multi_opts(skel->progs.test_uretprobe,
						      binary, pattern, opts);
	if (!ASSERT_OK_PTR(link2, "bpf_program__attach_uprobe_multi_opts_retprobe"))
		goto cleanup;

	uprobe_multi_test_run(skel);

cleanup:
	bpf_link__destroy(link2);
	bpf_link__destroy(link1);
	uprobe_multi__destroy(skel);
}

static void test_attach_api_pattern(void)
{
	LIBBPF_OPTS(bpf_uprobe_multi_opts, opts);

	test_attach_api("/proc/self/exe", "uprobe_multi_func_*", &opts);
	test_attach_api("/proc/self/exe", "uprobe_multi_func_?", &opts);
}

static void test_attach_api_syms(void)
{
	LIBBPF_OPTS(bpf_uprobe_multi_opts, opts);
	const char *syms[3] = {
		"uprobe_multi_func_1",
		"uprobe_multi_func_2",
		"uprobe_multi_func_3",
	};

	opts.syms = syms;
	opts.cnt = ARRAY_SIZE(syms);
	test_attach_api("/proc/self/exe", NULL, &opts);
}

void test_link_api(void)
{
	int prog_fd, link1_fd = -1, link2_fd = -1;
	LIBBPF_OPTS(bpf_link_create_opts, opts);
	struct uprobe_multi *skel = NULL;
	unsigned long *offsets = NULL;
	const char *syms[3] = {
		"uprobe_multi_func_1",
		"uprobe_multi_func_2",
		"uprobe_multi_func_3",
	};
	const char *paths[3] = {
		"/proc/self/exe",
		"/proc/self/exe",
		"/proc/self/exe",
	};
	int err;

	err = elf_find_multi_func_offset(paths[0], 3, syms, (unsigned long **) &offsets);
	if (!ASSERT_OK(err, "elf_find_multi_func_offset"))
		return;

	opts.uprobe_multi.paths = paths;
	opts.uprobe_multi.offsets = offsets;
	opts.uprobe_multi.cnt = ARRAY_SIZE(syms);

	skel = uprobe_multi__open_and_load();
	if (!ASSERT_OK_PTR(skel, "uprobe_multi"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.test_uprobe);
	link1_fd = bpf_link_create(prog_fd, 0, BPF_TRACE_UPROBE_MULTI, &opts);
	if (!ASSERT_GE(link1_fd, 0, "link_fd"))
		goto cleanup;

	opts.kprobe_multi.flags = BPF_F_UPROBE_MULTI_RETURN;
	prog_fd = bpf_program__fd(skel->progs.test_uretprobe);
	link2_fd = bpf_link_create(prog_fd, 0, BPF_TRACE_UPROBE_MULTI, &opts);
	if (!ASSERT_GE(link2_fd, 0, "link_fd"))
		goto cleanup;

	uprobe_multi_test_run(skel);

cleanup:
	if (link1_fd != -1)
		close(link1_fd);
	if (link2_fd != -1)
		close(link2_fd);

	uprobe_multi__destroy(skel);
	free(offsets);
}

void test_uprobe_multi_test(void)
{
	if (test__start_subtest("skel_api"))
		test_skel_api();
	if (test__start_subtest("attach_api_pattern"))
		test_attach_api_pattern();
	if (test__start_subtest("attach_api_syms"))
		test_attach_api_syms();
	if (test__start_subtest("link_api"))
		test_link_api();
}
