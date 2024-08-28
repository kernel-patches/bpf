// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "kfunc_obtain.skel.h"

void test_kfunc_obtain(void)
{
	if (env.has_testmod)
		RUN_TESTS(kfunc_obtain);
}
