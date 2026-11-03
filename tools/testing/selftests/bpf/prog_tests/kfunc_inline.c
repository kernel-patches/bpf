// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <stdlib.h>
#include "kfunc_inline.skel.h"
#include "kfunc_inline_jit.skel.h"

static __u64 rol64(__u64 x, unsigned int n)
{
	n &= 63;
	return n ? x << n | x >> (64 - n) : x;
}

static __u64 mix(__u64 a)
{
	return (a >> 7) ^ ((a << 3) + (a >> 11)) ^ (a * 5);
}

static __u64 rand64(void)
{
	return (__u64)rand() << 62 ^ (__u64)rand() << 31 ^ rand();
}

/* Compare kfuncs that the JIT may inline with their C definitions */
static void check_random(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct kfunc_inline *skel;
	int i, fd, err;

	skel = kfunc_inline__open_and_load();
	if (!ASSERT_OK_PTR(skel, "kfunc_inline__open_and_load"))
		return;
	fd = bpf_program__fd(skel->progs.kfunc_inline);
	srand(42);
	for (i = 0; i < 1000; i++) {
		__u64 x = rand64(), y = i % 7 ? rand64() : 0, c = i % 3 ? rand64() : 0;
		unsigned int n = rand() % 70;

		skel->bss->in_x = x;
		skel->bss->in_y = y;
		skel->bss->in_n = n;
		skel->bss->in_c = c;
		err = bpf_prog_test_run_opts(fd, &opts);
		if (!ASSERT_OK(err, "bpf_prog_test_run_opts"))
			break;
		if (!ASSERT_EQ(skel->bss->out_rol, rol64(x, n), "rol64") ||
		    !ASSERT_EQ(skel->bss->out_sel, c ? x : y, "select64") ||
		    !ASSERT_EQ(skel->bss->out_lt, x < y, "lt") ||
		    !ASSERT_EQ(skel->bss->out_mix, mix(x), "mix") ||
		    !ASSERT_EQ(skel->bss->out_div, y ? x / y : 0, "div"))
			break;
	}
	kfunc_inline__destroy(skel);
}

static bool kfuncs_instrumented(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct kfunc_inline *skel;
	bool ret = false;
	int err;

	skel = kfunc_inline__open_and_load();
	if (!ASSERT_OK_PTR(skel, "kfunc_inline__open_and_load"))
		return false;
	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.instrumented), &opts);
	if (ASSERT_OK(err, "instrumented"))
		ret = opts.retval;
	kfunc_inline__destroy(skel);
	return ret;
}

/* Not in verifier.c: its tests run without CAP_SYS_ADMIN, which libbpf needs
 * to find the bpf_testmod kfuncs.
 */
void test_kfunc_inline(void)
{
	if (!env.has_testmod) {
		test__skip();
		return;
	}
	if (test__start_subtest("random"))
		check_random();
	if (kfuncs_instrumented()) {
		printf("%s:SKIP:the kfuncs are instrumented, the JIT calls them\n", __func__);
		test__skip();
		return;
	}
	RUN_TESTS(kfunc_inline_jit);
}
