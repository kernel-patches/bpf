// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Hengqi Chen */

#include <test_progs.h>
#include "test_uprobe.skel.h"

static FILE *urand_spawn(int *pid)
{
	FILE *f;

	/* urandom_read's stdout is wired into f */
	f = popen("./urandom_read 1 report-pid", "r");
	if (!f)
		return NULL;

	if (fscanf(f, "%d", pid) != 1) {
		pclose(f);
		errno = EINVAL;
		return NULL;
	}

	return f;
}

static int urand_trigger(FILE **urand_pipe)
{
	int exit_code;

	/* pclose() waits for child process to exit and returns their exit code */
	exit_code = pclose(*urand_pipe);
	*urand_pipe = NULL;

	return exit_code;
}

static void test_uprobe_urandlib(void)
{
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);
	struct test_uprobe *skel;
	FILE *urand_pipe = NULL;
	int urand_pid = 0, err;

	skel = test_uprobe__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	urand_pipe = urand_spawn(&urand_pid);
	if (!ASSERT_OK_PTR(urand_pipe, "urand_spawn"))
		goto cleanup;

	skel->bss->my_pid = urand_pid;

	/* Manual attach uprobe to urandlib_api
	 * There are two `urandlib_api` symbols in .dynsym section:
	 *   - urandlib_api@LIBURANDOM_READ_1.0.0
	 *   - urandlib_api@@LIBURANDOM_READ_2.0.0
	 * Both are global bind and would cause a conflict if user
	 * specify the symbol name without a version suffix
	 */
	uprobe_opts.func_name = "urandlib_api";
	skel->links.test4 = bpf_program__attach_uprobe_opts(skel->progs.test4,
							    urand_pid,
							    "./liburandom_read.so",
							    0 /* offset */,
							    &uprobe_opts);
	if (!ASSERT_ERR_PTR(skel->links.test4, "urandlib_api_attach_conflict"))
		goto cleanup;

	uprobe_opts.func_name = "urandlib_api@LIBURANDOM_READ_1.0.0";
	skel->links.test4 = bpf_program__attach_uprobe_opts(skel->progs.test4,
							    urand_pid,
							    "./liburandom_read.so",
							    0 /* offset */,
							    &uprobe_opts);
	if (!ASSERT_OK_PTR(skel->links.test4, "urandlib_api_attach_ok"))
		goto cleanup;

	/* Auto attach 3 u[ret]probes to urandlib_api_sameoffset */
	err = test_uprobe__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto cleanup;

	/* trigger urandom_read */
	ASSERT_OK(urand_trigger(&urand_pipe), "urand_exit_code");

	ASSERT_EQ(skel->bss->test1_result, 1, "urandlib_api_sameoffset");
	ASSERT_EQ(skel->bss->test2_result, 1, "urandlib_api_sameoffset@v1");
	ASSERT_EQ(skel->bss->test3_result, 3, "urandlib_api_sameoffset@@v2");
	ASSERT_EQ(skel->bss->test4_result, 1, "urandlib_api");

cleanup:
	if (urand_pipe)
		pclose(urand_pipe);
	test_uprobe__destroy(skel);
}

static noinline void uprobe_unique_trigger(void)
{
        asm volatile ("");
}

static void test_uprobe_unique(void)
{
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts,
		.func_name = "uprobe_unique_trigger",
	);
	struct bpf_link *link_1, *link_2 = NULL;
	struct bpf_program *prog_1, *prog_2;
	struct test_uprobe *skel;

	skel = test_uprobe__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_uprobe__open_and_load"))
		return;

	skel->bss->my_pid = getpid();

	prog_1 = skel->progs.test1;
	prog_2 = skel->progs.test2;

	/* not-unique and unique */
	uprobe_opts.unique = false;
	link_1 = bpf_program__attach_uprobe_opts(prog_1, -1, "/proc/self/exe",
						 0 /* offset */, &uprobe_opts);
	if (!ASSERT_OK_PTR(link_1, "bpf_program__attach_uprobe_opts_1"))
		goto cleanup;

	uprobe_opts.unique = true;
	link_2 = bpf_program__attach_uprobe_opts(prog_2, -1, "/proc/self/exe",
						 0 /* offset */, &uprobe_opts);
	if (!ASSERT_ERR_PTR(link_2, "bpf_program__attach_uprobe_opts_2")) {
		bpf_link__destroy(link_2);
		goto cleanup;
	}

	bpf_link__destroy(link_1);

	/* unique and unique */
	uprobe_opts.unique = true;
	link_1 = bpf_program__attach_uprobe_opts(prog_1, -1, "/proc/self/exe",
						 0 /* offset */, &uprobe_opts);
	if (!ASSERT_OK_PTR(link_1, "bpf_program__attach_uprobe_opts_1"))
		goto cleanup;

	uprobe_opts.unique = true;
	link_2 = bpf_program__attach_uprobe_opts(prog_2, -1, "/proc/self/exe",
						 0 /* offset */, &uprobe_opts);
	if (!ASSERT_ERR_PTR(link_2, "bpf_program__attach_uprobe_opts_2")) {
		bpf_link__destroy(link_2);
		goto cleanup;
	}

	bpf_link__destroy(link_1);

	/* unique and not-unique */
	uprobe_opts.unique = true;
	link_1 = bpf_program__attach_uprobe_opts(prog_1, -1, "/proc/self/exe",
						 0 /* offset */, &uprobe_opts);
	if (!ASSERT_OK_PTR(link_1, "bpf_program__attach_uprobe_opts_1"))
		goto cleanup;

	uprobe_opts.unique = false;
	link_2 = bpf_program__attach_uprobe_opts(prog_2, -1, "/proc/self/exe",
						 0 /* offset */, &uprobe_opts);
	if (!ASSERT_ERR_PTR(link_2, "bpf_program__attach_uprobe_opts_2")) {
		bpf_link__destroy(link_2);
		goto cleanup;
	}

	bpf_link__destroy(link_1);

	/* not-unique and not-unique */
	uprobe_opts.unique = false;
	link_1 = bpf_program__attach_uprobe_opts(prog_1, -1, "/proc/self/exe",
						 0 /* offset */, &uprobe_opts);
	if (!ASSERT_OK_PTR(link_1, "bpf_program__attach_uprobe_opts_1"))
		goto cleanup;

	uprobe_opts.unique = false;
	link_2 = bpf_program__attach_uprobe_opts(prog_2, -1, "/proc/self/exe",
						 0 /* offset */, &uprobe_opts);
	if (!ASSERT_OK_PTR(link_2, "bpf_program__attach_uprobe_opts_2")) {
		bpf_link__destroy(link_1);
		goto cleanup;
	}

	uprobe_unique_trigger();

	ASSERT_EQ(skel->bss->test1_result, 1, "test1_result");
	ASSERT_EQ(skel->bss->test2_result, 1, "test2_result");

	bpf_link__destroy(link_1);
	bpf_link__destroy(link_2);

cleanup:
	test_uprobe__destroy(skel);
}

void test_uprobe(void)
{
	if (test__start_subtest("urandlib"))
		test_uprobe_urandlib();
	if (test__start_subtest("unique"))
		test_uprobe_unique();
}
