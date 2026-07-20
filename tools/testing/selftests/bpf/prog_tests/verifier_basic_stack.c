// SPDX-License-Identifier: GPL-2.0-only

#include <test_progs.h>

#include "cap_helpers.h"
#include "verifier_basic_stack.skel.h"

void test_verifier_basic_stack(void)
{
	struct test_loader tester = {};
	__u64 old_caps;
	int err;

	/* test_verifier tests are executed w/o CAP_SYS_ADMIN, do the same here */
	err = cap_disable_effective(1ULL << CAP_SYS_ADMIN, &old_caps);
	if (err) {
		PRINT_FAIL("failed to drop CAP_SYS_ADMIN: %i, %s\n", err, strerror(-err));
		return;
	}

	test_loader__run_subtests(&tester, "verifier_basic_stack",
				  verifier_basic_stack__elf_bytes);
	test_loader_fini(&tester);

	err = cap_enable_effective(old_caps, NULL);
	if (err)
		PRINT_FAIL("failed to restore CAP_SYS_ADMIN: %i, %s\n", err, strerror(-err));
}
