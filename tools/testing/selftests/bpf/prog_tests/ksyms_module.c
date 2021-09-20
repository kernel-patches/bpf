// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */

#include <test_progs.h>
#include <network_helpers.h>
#include "test_ksyms_module.lskel.h"
#include "test_ksyms_module_fail.lskel.h"
#include "test_ksyms_module_fail_toomany.lskel.h"

void test_ksyms_module_main(void)
{
	struct test_ksyms_module *skel;
	int retval;
	int err;

	if (!env.has_testmod) {
		test__skip();
		return;
	}

	skel = test_ksyms_module__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_ksyms_module__open_and_load"))
		return;

	err = bpf_prog_test_run(skel->progs.handler.prog_fd, 1, &pkt_v4, sizeof(pkt_v4),
				NULL, NULL, (__u32 *)&retval, NULL);
	if (!ASSERT_OK(err, "bpf_prog_test_run"))
		goto cleanup;
	ASSERT_EQ(retval, 0, "retval");
	ASSERT_EQ(skel->bss->out_bpf_testmod_ksym, 42, "bpf_testmod_ksym");
cleanup:
	test_ksyms_module__destroy(skel);
}

void test_ksyms_module_fail(void)
{
	struct test_ksyms_module_fail_toomany *skel2;
	struct test_ksyms_module_fail *skel1;

	skel1 = test_ksyms_module_fail__open_and_load();
	if (!ASSERT_EQ(skel1, NULL, "test_ksyms_module_fail__open_and_load"))
		test_ksyms_module_fail__destroy(skel1);

	skel2 = test_ksyms_module_fail_toomany__open_and_load();
	if (!ASSERT_EQ(skel2, NULL, "test_ksyms_module_fail_toomany__open_and_load"))
		test_ksyms_module_fail_toomany__destroy(skel2);
}

void test_ksyms_module(void)
{
	if (test__start_subtest("main"))
		test_ksyms_module_main();
	if (test__start_subtest("fail"))
		test_ksyms_module_fail();
}
