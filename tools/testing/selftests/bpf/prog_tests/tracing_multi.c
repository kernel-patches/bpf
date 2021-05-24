// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>

#ifdef __x86_64__
#include "tracing_multi_fentry_test.skel.h"
#include "trace_helpers.h"

static void multi_fentry_test(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct tracing_multi_fentry_test *skel = NULL;
	int err, prog_fd;

	skel = tracing_multi_fentry_test__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fentry_multi_skel_load"))
		goto cleanup;

	err = tracing_multi_fentry_test__attach(skel);
	if (!ASSERT_OK(err, "fentry_attach"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.test);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");

	ASSERT_EQ(skel->bss->test_result_1, 8, "test_result");

cleanup:
	tracing_multi_fentry_test__destroy(skel);
}

void __test_tracing_multi_test(void)
{
	if (test__start_subtest("fentry/simple"))
		multi_fentry_test();
}
#else
void __test_tracing_multi_test(void)
{
	test__skip();
}
#endif /* __x86_64__ */

void test_tracing_multi_test(void)
{
	__test_tracing_multi_test();
}
