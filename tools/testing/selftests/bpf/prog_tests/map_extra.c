// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "test_map_extra.skel.h"

void test_map_extra(void)
{
	struct test_map_extra *skel;

	if (!test__start_subtest("enum32_high"))
		return;

	skel = test_map_extra__open();
	if (!ASSERT_OK_PTR(skel, "test_map_extra__open"))
		return;

	ASSERT_EQ(bpf_map__map_extra(skel->maps.arena), 0x80000000ULL,
		  "map_extra");
	test_map_extra__destroy(skel);
}
