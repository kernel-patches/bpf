// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include <network_helpers.h>
#include "test_helper_module.lskel.h"
#include "test_helper_module.skel.h"

void test_helper_module_lskel(void)
{
	struct test_helper_module_lskel *skel;
	int retval;
	int err;

	if (!env.has_testmod) {
		test__skip();
		return;
	}

	skel = test_helper_module_lskel__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_helper_module_lskel__open_and_load"))
		return;
	err = bpf_prog_test_run(skel->progs.load.prog_fd, 1, &pkt_v4, sizeof(pkt_v4),
				NULL, NULL, (__u32 *)&retval, NULL);
	if (!ASSERT_OK(err, "bpf_prog_test_run"))
		goto cleanup;
	ASSERT_EQ(retval, 7, "retval");
cleanup:
	test_helper_module_lskel__destroy(skel);
}

void test_helper_module_libbpf(void)
{
	struct test_helper_module *skel;
	int retval, err;

	if (!env.has_testmod) {
		test__skip();
		return;
	}

	skel = test_helper_module__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_helper_module__open"))
		return;
	err = bpf_prog_test_run(bpf_program__fd(skel->progs.load), 1, &pkt_v4,
				sizeof(pkt_v4), NULL, NULL, (__u32 *)&retval, NULL);
	if (!ASSERT_OK(err, "bpf_prog_test_run"))
		goto cleanup;
	ASSERT_EQ(retval, 7, "retval");
cleanup:
	test_helper_module__destroy(skel);
}

void test_helper_module(void)
{
	if (test__start_subtest("lskel"))
		test_helper_module_lskel();
	if (test__start_subtest("libbpf"))
		test_helper_module_libbpf();
}
