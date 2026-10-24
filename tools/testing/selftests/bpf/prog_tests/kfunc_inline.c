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
		skel->bss->in_x = rand64();
		skel->bss->in_y = i % 7 ? rand64() : 0;
		skel->bss->in_n = rand() % 70;
		skel->bss->in_c = i % 3 ? rand64() : 0;
		err = bpf_prog_test_run_opts(fd, &opts);
		if (!ASSERT_OK(err, "bpf_prog_test_run_opts"))
			break;
		if (!ASSERT_EQ(skel->bss->out_rol, rol64(skel->bss->in_x, skel->bss->in_n), "rol64") ||
		    !ASSERT_EQ(skel->bss->out_sel,
			       skel->bss->in_c ? skel->bss->in_x : skel->bss->in_y, "select64") ||
		    !ASSERT_EQ(skel->bss->out_lt, skel->bss->in_x < skel->bss->in_y, "lt") ||
		    !ASSERT_EQ(skel->bss->out_mix, mix(skel->bss->in_x), "mix") ||
		    !ASSERT_EQ(skel->bss->out_div,
			       skel->bss->in_y ? skel->bss->in_x / skel->bss->in_y : 0, "div"))
			break;
	}
	kfunc_inline__destroy(skel);
}

/* Not in verifier.c: its tests run without CAP_SYS_ADMIN, which libbpf needs
 * to find the bpf_testmod kfuncs.
 */
void test_kfunc_inline(void)
{
	if (test__start_subtest("random"))
		check_random();
	RUN_TESTS(kfunc_inline_jit);
}
