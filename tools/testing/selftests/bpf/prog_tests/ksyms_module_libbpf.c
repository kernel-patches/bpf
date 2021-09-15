// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "test_ksyms_module_libbpf.skel.h"

void test_ksyms_module_libbpf(void)
{
	struct test_ksyms_module_libbpf *skel;

	if (!env.has_testmod) {
		test__skip();
		return;
	}

	skel = test_ksyms_module_libbpf__open_and_load();
	if (!ASSERT_EQ(skel, NULL, "test_ksyms_module__open_and_load"))
		test_ksyms_module_libbpf__destroy(skel);
}
