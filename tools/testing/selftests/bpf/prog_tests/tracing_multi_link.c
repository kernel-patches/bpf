// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 ChinaTelecom */

#include <test_progs.h>
#include "bpf/libbpf_internal.h"

#include "tracing_multi_test.skel.h"
#include "tracing_multi_override.skel.h"
#include "fentry_multi_empty.skel.h"

static void test_run(struct tracing_multi_test *skel)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	int err, prog_fd;

	skel->bss->pid = getpid();
	prog_fd = bpf_program__fd(skel->progs.fentry_cookie_test1);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, 0, "test_run");

	ASSERT_EQ(skel->bss->fentry_test1_result, 1, "fentry_test1_result");
	ASSERT_EQ(skel->bss->fentry_test2_result, 1, "fentry_test2_result");
	ASSERT_EQ(skel->bss->fentry_test3_result, 1, "fentry_test3_result");
	ASSERT_EQ(skel->bss->fentry_test4_result, 1, "fentry_test4_result");
	ASSERT_EQ(skel->bss->fentry_test5_result, 1, "fentry_test5_result");
	ASSERT_EQ(skel->bss->fentry_test6_result, 1, "fentry_test6_result");
	ASSERT_EQ(skel->bss->fentry_test7_result, 1, "fentry_test7_result");
	ASSERT_EQ(skel->bss->fentry_test8_result, 1, "fentry_test8_result");
}

static void test_skel_auto_api(void)
{
	struct tracing_multi_test *skel;
	int err;

	skel = tracing_multi_test__open_and_load();
	if (!ASSERT_OK_PTR(skel, "tracing_multi_test__open_and_load"))
		return;

	/* disable all programs that should fail */
	bpf_program__set_autoattach(skel->progs.fentry_fail_test1, false);
	bpf_program__set_autoattach(skel->progs.fentry_fail_test2, false);
	bpf_program__set_autoattach(skel->progs.fentry_fail_test3, false);
	bpf_program__set_autoattach(skel->progs.fentry_fail_test4, false);
	bpf_program__set_autoattach(skel->progs.fentry_fail_test5, false);
	bpf_program__set_autoattach(skel->progs.fentry_fail_test6, false);

	bpf_program__set_autoattach(skel->progs.fexit_fail_test1, false);
	bpf_program__set_autoattach(skel->progs.fexit_fail_test2, false);
	bpf_program__set_autoattach(skel->progs.fexit_fail_test3, false);

	err = tracing_multi_test__attach(skel);
	if (!ASSERT_OK(err, "tracing_multi_test__attach"))
		goto cleanup;

	test_run(skel);

cleanup:
	tracing_multi_test__destroy(skel);
}

static void test_skel_manual_api(void)
{
	struct tracing_multi_test *skel;
	struct bpf_link *link;
	int err;

	skel = tracing_multi_test__open_and_load();
	if (!ASSERT_OK_PTR(skel, "tracing_multi_test__open_and_load"))
		return;

#define ATTACH_PROG(name, success)					\
do {									\
	link = bpf_program__attach(skel->progs.name);			\
	err = libbpf_get_error(link);					\
	if (!ASSERT_OK(success ? err : !err,				\
		       "bpf_program__attach: " #name))			\
		goto cleanup;						\
	skel->links.name = err ? NULL : link;				\
} while (0)

	ATTACH_PROG(fentry_success_test1, true);
	ATTACH_PROG(fentry_success_test2, true);
	ATTACH_PROG(fentry_success_test3, true);
	ATTACH_PROG(fentry_success_test4, true);

	ATTACH_PROG(fexit_success_test1, true);
	ATTACH_PROG(fexit_success_test2, true);

	ATTACH_PROG(fentry_fail_test1, false);
	ATTACH_PROG(fentry_fail_test2, false);
	ATTACH_PROG(fentry_fail_test3, false);
	ATTACH_PROG(fentry_fail_test4, false);
	ATTACH_PROG(fentry_fail_test5, false);
	ATTACH_PROG(fentry_fail_test6, false);

	ATTACH_PROG(fexit_fail_test1, false);
	ATTACH_PROG(fexit_fail_test2, false);
	ATTACH_PROG(fexit_fail_test3, false);

	ATTACH_PROG(fentry_cookie_test1, true);

	test_run(skel);

cleanup:
	tracing_multi_test__destroy(skel);
}

static void test_attach_api(void)
{
	LIBBPF_OPTS(bpf_trace_multi_opts, opts);
	struct tracing_multi_test *skel;
	struct bpf_link *link;
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
	__u64 cookies[] = {1, 7, 2, 3, 4, 5, 6, 8};

	skel = tracing_multi_test__open_and_load();
	if (!ASSERT_OK_PTR(skel, "tracing_multi_test__open_and_load"))
		return;

	opts.syms = syms;
	opts.cookies = cookies;
	opts.cnt = ARRAY_SIZE(syms);
	link = bpf_program__attach_trace_multi_opts(skel->progs.fentry_cookie_test1,
						    &opts);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_trace_multi_opts"))
		goto cleanup;
	skel->links.fentry_cookie_test1 = link;

	skel->bss->test_cookie = true;
	test_run(skel);
cleanup:
	tracing_multi_test__destroy(skel);
}

static void test_attach_bench(bool kernel)
{
	LIBBPF_OPTS(bpf_trace_multi_opts, opts);
	struct fentry_multi_empty *skel;
	long attach_start_ns, attach_end_ns;
	long detach_start_ns, detach_end_ns;
	double attach_delta, detach_delta;
	struct bpf_link *link = NULL;
	char **syms = NULL;
	size_t cnt = 0;

	if (!ASSERT_OK(bpf_get_ksyms(&syms, &cnt, kernel), "get_syms"))
		return;

	skel = fentry_multi_empty__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fentry_multi_empty__open_and_load"))
		goto cleanup;

	opts.syms = (const char **) syms;
	opts.cnt = cnt;
	opts.skip_invalid = true;

	attach_start_ns = get_time_ns();
	link = bpf_program__attach_trace_multi_opts(skel->progs.fentry_multi_empty,
						    &opts);
	attach_end_ns = get_time_ns();

	if (!ASSERT_OK_PTR(link, "bpf_program__attach_trace_multi_opts"))
		return;

	detach_start_ns = get_time_ns();
	bpf_link__destroy(link);
	detach_end_ns = get_time_ns();

	attach_delta = (attach_end_ns - attach_start_ns) / 1000000000.0;
	detach_delta = (detach_end_ns - detach_start_ns) / 1000000000.0;

	printf("%s: found %lu functions\n", __func__, opts.cnt);
	printf("%s: attached in %7.3lfs\n", __func__, attach_delta);
	printf("%s: detached in %7.3lfs\n", __func__, detach_delta);

cleanup:
	fentry_multi_empty__destroy(skel);
	if (syms)
		free(syms);
}

static void test_attach_override(bool fentry_over_multi)
{
	struct tracing_multi_override *skel;
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct bpf_link *link;
	int err, prog_fd;

	skel = tracing_multi_override__open_and_load();
	if (!ASSERT_OK_PTR(skel, "tracing_multi_test__open_and_load"))
		goto cleanup;

	if (fentry_over_multi) {
		ATTACH_PROG(fentry_multi_override_test1, true);
		ATTACH_PROG(fentry_override_test1, true);
	} else {
		ATTACH_PROG(fentry_override_test1, true);
		ATTACH_PROG(fentry_multi_override_test1, true);
	}

	prog_fd = bpf_program__fd(skel->progs.fentry_multi_override_test1);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, 0, "test_run");

	ASSERT_EQ(skel->data->fentry_override_test1_result, 3,
		  "fentry_override_test1_result");
cleanup:
	tracing_multi_override__destroy(skel);
}

static void test_attach_multi(void)
{
	struct tracing_multi_override *skel;
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct bpf_link *link;
	int err, prog_fd;

	skel = tracing_multi_override__open();
	if (!ASSERT_OK_PTR(skel, "tracing_multi_test__open"))
		goto cleanup;

	/* don't load fentry_override_test1, it will create a trampoline */
	bpf_program__set_autoload(skel->progs.fentry_override_test1, false);
	err = tracing_multi_override__load(skel);
	if (!ASSERT_OK(err, "tracing_multi_test__load"))
		goto cleanup;

	ATTACH_PROG(fentry_multi_override_test1, true);
	ATTACH_PROG(fentry_multi_override_test2, true);

	prog_fd = bpf_program__fd(skel->progs.fentry_multi_override_test1);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, 0, "test_run");

	ASSERT_EQ(skel->data->fentry_override_test1_result, 4,
		  "fentry_override_test1_result");
cleanup:
	tracing_multi_override__destroy(skel);
}

void serial_test_tracing_multi_attach_bench(void)
{
	if (test__start_subtest("kernel"))
		test_attach_bench(true);
	if (test__start_subtest("modules"))
		test_attach_bench(false);
}

void test_tracing_multi_attach_test(void)
{
	if (test__start_subtest("skel_auto_api"))
		test_skel_auto_api();
	if (test__start_subtest("skel_manual_api"))
		test_skel_manual_api();
	if (test__start_subtest("attach_api"))
		test_attach_api();
	if (test__start_subtest("attach_over_multi"))
		test_attach_override(true);
	if (test__start_subtest("attach_over_fentry"))
		test_attach_override(false);
	if (test__start_subtest("attach_multi"))
		test_attach_multi();
}
