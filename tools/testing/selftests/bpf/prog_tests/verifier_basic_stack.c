// SPDX-License-Identifier: GPL-2.0-only

#include <test_progs.h>

#include "verifier_basic_stack.skel.h"

void test_verifier_basic_stack(void)
{
	struct test_loader tester = {};

	test_loader__run_subtests(&tester, "verifier_basic_stack",
				  verifier_basic_stack__elf_bytes);
	test_loader_fini(&tester);
}
