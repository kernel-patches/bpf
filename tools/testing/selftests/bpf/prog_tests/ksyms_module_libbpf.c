// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include <network_helpers.h>
#include "test_ksyms_module_libbpf.skel.h"

void test_ksyms_module_libbpf(void)
{
	struct test_ksyms_module_libbpf *skel;
	int retval, err;

	if (!env.has_testmod) {
		test__skip();
		return;
	}

	skel = test_ksyms_module_libbpf__open();
	if (!ASSERT_OK_PTR(skel, "test_ksyms_module_libbpf__open"))
		return;
	err = bpf_program__set_autoload(skel->progs.load_fail1, false);
	if (!ASSERT_OK(err, "bpf_program__set_autoload false load_fail1"))
		goto cleanup;
	err = bpf_program__set_autoload(skel->progs.load_fail2, false);
	if (!ASSERT_OK(err, "bpf_program__set_autoload false load_fail2"))
		goto cleanup;
	err = test_ksyms_module_libbpf__load(skel);
	if (!ASSERT_OK(err, "test_ksyms_module_libbpf__load"))
		goto cleanup;
	err = bpf_prog_test_run(bpf_program__fd(skel->progs.handler), 1, &pkt_v4,
				sizeof(pkt_v4), NULL, NULL, (__u32 *)&retval, NULL);
	if (!ASSERT_OK(err, "bpf_prog_test_run"))
		goto cleanup;
	ASSERT_EQ(retval, 0, "retval");
	ASSERT_EQ(skel->bss->out_bpf_testmod_ksym, 42, "bpf_testmod_ksym");

	err = bpf_program__load(skel->progs.load_fail1, "GPL", 0);
	if (!ASSERT_NEQ(err, 0, "bpf_program__load load_fail1"))
		goto cleanup;
	err = bpf_program__load(skel->progs.load_fail2, "GPL", 0);
	if (!ASSERT_NEQ(err, 0, "bpf_program__load load_fail2"))
		goto cleanup;
cleanup:
	test_ksyms_module_libbpf__destroy(skel);
}
