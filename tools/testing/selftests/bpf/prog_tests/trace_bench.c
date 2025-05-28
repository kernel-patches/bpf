// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 ChinaTelecom */

#include <test_progs.h>
#include "bpf/libbpf_internal.h"

#include "fentry_multi_empty.skel.h"
#include "fentry_empty.skel.h"
#include "kprobe_multi_empty.skel.h"
#include "trace_bench.skel.h"

static void test_bench_run(const char *name)
{
	struct trace_bench *skel;
	__u64 bench_result;
	int err;

	skel = trace_bench__open_and_load();
	if (!ASSERT_OK_PTR(skel, "trace_bench__open_and_load"))
		return;

	err = trace_bench__attach(skel);
	if (!ASSERT_OK(err, "trace_bench__attach"))
		goto cleanup;

	ASSERT_OK(trigger_module_test_read(1), "trigger_read");

	bench_result = skel->bss->bench_result / 1000;
	printf("bench time for %s: %lld.%03lldms\n", name, bench_result / 1000,
	       bench_result % 1000);
cleanup:
	trace_bench__destroy(skel);
}

static void test_fentry_multi(bool load_all, char *name)
{
	LIBBPF_OPTS(bpf_trace_multi_opts, opts);
	struct fentry_multi_empty *skel;
	char **syms = NULL;
	struct bpf_link *link;
	size_t cnt = 0;
	int err;

	skel = fentry_multi_empty__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fentry_multi_empty__open_and_load"))
		goto cleanup;

	if (!load_all) {
		err = fentry_multi_empty__attach(skel);
		if (!ASSERT_OK(err, "fentry_multi_empty__attach"))
			goto cleanup;
		goto do_test;
	}

	if (!ASSERT_OK(bpf_get_ksyms(&syms, &cnt, true), "get_syms"))
		return;
	opts.syms = (const char **) syms;
	opts.cnt = cnt;
	opts.skip_invalid = true;
	link = bpf_program__attach_trace_multi_opts(skel->progs.fentry_multi_empty,
						    &opts);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_trace_multi_opts"))
		goto cleanup;
	skel->links.fentry_multi_empty = link;
	printf("attach %d functions before testings\n", (int)opts.cnt);

do_test:
	test_bench_run(name);
cleanup:
	fentry_multi_empty__destroy(skel);
	if (syms)
		free(syms);
}

static void test_fentry_single(void)
{
	struct fentry_empty *skel;
	int err;

	skel = fentry_empty__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fentry_empty__open_and_load"))
		return;

	err = fentry_empty__attach(skel);
	if (!ASSERT_OK(err, "fentry_empty__attach"))
		goto cleanup;

	test_bench_run("fentry_single");
cleanup:
	fentry_empty__destroy(skel);
}

static void test_kprobe_multi(bool load_all, char *name)
{
	LIBBPF_OPTS(bpf_kprobe_multi_opts, opts);
	char *test_func = "bpf_fentry_test1";
	struct kprobe_multi_empty *skel;
	struct bpf_link *link;
	char **syms = NULL;
	size_t cnt = 0;

	if (!ASSERT_OK(bpf_get_ksyms(&syms, &cnt, true), "get_syms"))
		return;

	skel = kprobe_multi_empty__open_and_load();
	if (!ASSERT_OK_PTR(skel, "kprobe_multi_empty__open_and_load"))
		goto cleanup;

	if (load_all) {
		opts.syms = (const char **) syms;
		opts.cnt = cnt;
	} else {
		opts.syms = (const char **) &test_func;
		opts.cnt = 1;
	}
	link = bpf_program__attach_kprobe_multi_opts(skel->progs.test_kprobe_empty,
						     NULL, &opts);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_kprobe_multi_opts"))
		goto cleanup;
	skel->links.test_kprobe_empty = link;

	if (load_all)
		printf("attach %d functions before testings\n", (int)opts.cnt);
	test_bench_run(name);

cleanup:
	kprobe_multi_empty__destroy(skel);
	if (syms)
		free(syms);
}

void test_trace_bench(void)
{
	if (test__start_subtest("nop"))
		test_bench_run("nop");

	if (test__start_subtest("fentry_single"))
		test_fentry_single();

	if (test__start_subtest("fentry_multi_single"))
		test_fentry_multi(false, "fentry_multi_single");
	if (test__start_subtest("fentry_multi_all"))
		test_fentry_multi(true, "fentry_multi_all");

	if (test__start_subtest("kprobe_multi_single"))
		test_kprobe_multi(false, "kprobe_multi_single");
	if (test__start_subtest("kprobe_multi_all"))
		test_kprobe_multi(true, "kprobe_multi_all");
}
