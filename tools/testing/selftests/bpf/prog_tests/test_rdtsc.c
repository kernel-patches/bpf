// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2023 Intel Corporation */

#include "test_progs.h"
#include "test_rdtsc.skel.h"

#ifdef __x86_64__

static inline u64 _rdtsc(void)
{
	u32 low, high;

	__asm__ __volatile__("rdtscp" : "=a" (low), "=d" (high));
	return ((u64)high << 32) | low;
}

static int rdtsc(struct test_rdtsc *skel)
{
	int err, prog_fd;
	u64 user_c1, user_c2;

	LIBBPF_OPTS(bpf_test_run_opts, topts);

	err = test_rdtsc__attach(skel);
	if (!ASSERT_OK(err, "test_rdtsc_attach"))
		return err;

	user_c1 = _rdtsc();

	prog_fd = bpf_program__fd(skel->progs.test1);
	err = bpf_prog_test_run_opts(prog_fd, &topts);

	user_c2 = _rdtsc();

	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, 0, "test_run");

	test_rdtsc__detach(skel);

	ASSERT_GE(skel->bss->c1, user_c1, "bpf c1 > user c1");
	ASSERT_GE(user_c2, skel->bss->c2, "user c2 > bpf c2");
	ASSERT_GE(skel->bss->c2, user_c1, "bpf c2 > bpf c1");
	ASSERT_GE(user_c2, user_c1, "user c2 > user c1");

	return 0;
}
#endif

void test_rdtsc(void)
{
#ifdef __x86_64__
	struct test_rdtsc *skel;
	int err;

	skel = test_rdtsc__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_rdtsc_skel_load"))
		goto cleanup;
	err = rdtsc(skel);
	ASSERT_OK(err, "rdtsc");

cleanup:
	test_rdtsc__destroy(skel);
#else
	printf("%s:SKIP:bpf_rdtsc() kfunc not supported\n", __func__);
	test__skip();
#endif
}
