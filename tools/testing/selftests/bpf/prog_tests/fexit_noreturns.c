// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "fexit_noreturns.skel.h"

void test_fexit_noreturns(void)
{
	struct fexit_noreturns *fexit_skel;

	fexit_skel = fexit_noreturns__open_and_load();
	ASSERT_NULL(fexit_skel, "fexit_load");
	ASSERT_EQ(errno, EINVAL, "can't load fexit_noreturns");
}
