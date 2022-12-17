// SPDX-License-Identifier: GPL-2.0-only
#include <test_progs.h>

#include "check_ids_limits.skel.h"

#define TEST_SET(skel)			\
	void test_##skel(void)		\
	{				\
		RUN_TESTS(skel);	\
	}

TEST_SET(check_ids_limits)
