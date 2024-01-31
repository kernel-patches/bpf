// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024, Oracle and/or its affiliates. */

#include <test_progs.h>

#include <dlfcn.h>

#include "../sdt.h"

#include "test_urdt.skel.h"
#include "test_urdt_shared.skel.h"

static volatile __u64 bla = 0xFEDCBA9876543210ULL;

static void subtest_basic_urdt(void)
{
	LIBBPF_OPTS(bpf_urdt_opts, opts);
	struct test_urdt *skel;
	struct test_urdt__bss *bss;
	long x = 1;
	int y = 42;
	int err;
	int i;

	skel = test_urdt__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	bss = skel->bss;
	bss->my_pid = getpid();

	err = test_urdt__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto cleanup;

	/* urdt0 won't be auto-attached */
	opts.urdt_cookie = 0xcafedead;
	opts.urdt_nargs = 0;
	skel->links.urdt0 = bpf_program__attach_urdt(skel->progs.urdt0,
						     0 /*self*/, "/proc/self/exe",
						     "dyn", "urdt0", &opts);
	if (!ASSERT_OK_PTR(skel->links.urdt0, "urdt0_link"))
		goto cleanup;

	BPF_URDT_PROBE0("dyn", "urdt0");

	ASSERT_EQ(bss->urdt0_called, 1, "urdt0_called");

	ASSERT_EQ(bss->urdt0_cookie, 0xcafedead, "urdt0_cookie");
	ASSERT_EQ(bss->urdt0_arg_cnt, 0, "urdt0_arg_cnt");
	ASSERT_EQ(bss->urdt0_arg_ret, -ENOENT, "urdt0_arg_ret");

	BPF_URDT_PROBE3("dyn", "urdt3", x, y, &bla);

	ASSERT_EQ(bss->urdt3_called, 1, "urdt3_called");
	/* ensure the other 3-arg URDT probe does not trigger */
	ASSERT_EQ(bss->urdt3alt_called, 0, "urdt3alt_notcalled");
	/* auto-attached urdt3 gets default zero cookie value */
	ASSERT_EQ(bss->urdt3_cookie, 0, "urdt3_cookie");
	ASSERT_EQ(bss->urdt3_arg_cnt, 3, "urdt3_arg_cnt");

	ASSERT_EQ(bss->urdt3_arg1, 1, "urdt3_arg1");
	ASSERT_EQ(bss->urdt3_arg2, 42, "urdt3_arg2");
	ASSERT_EQ((long)bss->urdt3_arg3, (long)&bla, "urdt3_arg3");

	/* now call alternative 3-arg function, and make sure dyn/urdt3
	 * does not trigger.
	 */
	BPF_URDT_PROBE3("dyn", "urdt3alt", y, &bla, x);

	ASSERT_EQ(bss->urdt3alt_called, 1, "urdt3alt_called");
	ASSERT_EQ(bss->urdt3_called, 1, "urdt3_notcalled");

	ASSERT_EQ(bss->urdt3alt_arg1, 42, "urdt3alt_arg1");
	ASSERT_EQ((long)bss->urdt3alt_arg2, (long)&bla, "urdt3_arg3");
	ASSERT_EQ(bss->urdt3alt_arg3, 1, "urdt3alt_arg3");

	BPF_URDT_PROBE11("dyn", "urdt11", 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11);

	ASSERT_EQ(bss->urdt11_called, 1, "urdt11_called");
	ASSERT_EQ(bss->urdt3_called, 1, "urdt3_called");
	for (i = 0; i < 11; i++)
		ASSERT_EQ(bss->urdt11_args[i], i + 1, "urdt11_arg");

cleanup:
	test_urdt__destroy(skel);
}

#define LIBBPF_SO_PATH	"./tools/build/libbpf/libbpf.so"

/* verify shared object attach/firing works for libbpf.so */
static void subtest_shared_urdt(void)
{
	LIBBPF_OPTS(bpf_urdt_opts, opts);
	struct test_urdt_shared *skel;
	void *dlh;
	void (*probe0)(const char *provider, const char *probe);
	void (*probe4)(const char *provider, const char *probe, long arg1, long arg2,
		       long arg3, long arg4);
	struct test_urdt_shared__bss *bss;
	long x = 1;
	int y = 42;
	int z = 3;
	int err;

	skel = test_urdt_shared__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;
	bss = skel->bss;
	bss->my_pid = getpid();

	err = test_urdt_shared__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto cleanup;

	/* urdt0 won't be auto-attached */
	opts.urdt_cookie = 0xcafedead;
	opts.urdt_nargs = 0;
	skel->links.urdt0 = bpf_program__attach_urdt(skel->progs.urdt0,
						     -1 /* all */,
						     LIBBPF_SO_PATH,
						     "dyn", "urdt0", &opts);
	if (!ASSERT_OK_PTR(skel->links.urdt0, "urdt0_link"))
		goto cleanup;

	/* test_progs is statically linked with libbpf, so we need to dlopen/dlsym
	 * probe firing functions in the shared object we have attached to in order
	 * to trigger probe firing.  If a program is dynamically linked to libbpf
	 * for probe firing, this won't be needed, but we want to make sure this
	 * mode of operation works as it will likely be the common case.
	 */
	dlh = dlopen(LIBBPF_SO_PATH, RTLD_NOW);
	if (!ASSERT_NEQ(dlh, NULL, "dlopen"))
		goto cleanup;
	probe0 = dlsym(dlh, "bpf_urdt__probe0");
	if (!ASSERT_NEQ(probe0, NULL, "dlsym_probe0"))
		goto cleanup;
	probe4 = dlsym(dlh, "bpf_urdt__probe4");
	if (!ASSERT_NEQ(probe4, NULL, "dlsym_probe4"))
		goto cleanup;

	probe0("dyn", "urdt0");

	ASSERT_EQ(bss->urdt0_called, 1, "urdt0_called");

	ASSERT_EQ(bss->urdt0_cookie, 0xcafedead, "urdt0_cookie");
	ASSERT_EQ(bss->urdt0_arg_cnt, 0, "urdt0_arg_cnt");
	ASSERT_EQ(bss->urdt0_arg_ret, -ENOENT, "urdt0_arg_ret");

	probe4("dyn", "urdt4", (long)x, (long)y, (long)z, (long)&bla);

	ASSERT_EQ(bss->urdt4_called, 1, "urdt4_called");
	/* auto-attached urdt4 gets default zero cookie value */
	ASSERT_EQ(bss->urdt4_cookie, 0, "urdt4_cookie");
	ASSERT_EQ(bss->urdt4_arg_cnt, 4, "urdt4_arg_cnt");

	ASSERT_EQ(bss->urdt4_arg1, 1, "urdt4_arg1");
	ASSERT_EQ(bss->urdt4_arg2, 42, "urdt4_arg2");
	ASSERT_EQ(bss->urdt4_arg3, 3, "urdt4_arg3");
	ASSERT_EQ((long)bss->urdt4_arg4, (long)&bla, "urdt4_arg4");
cleanup:
	if (dlh)
		dlclose(dlh);
	test_urdt_shared__destroy(skel);
}

void test_urdt(void)
{
	if (test__start_subtest("basic"))
		subtest_basic_urdt();
	if (test__start_subtest("shared"))
		subtest_shared_urdt();
}
