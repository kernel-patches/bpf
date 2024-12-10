// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>

#include "bpf_smc.skel.h"

static void load(void)
{
	struct bpf_smc *skel;
	int ret;

	skel = bpf_smc__open_and_load();
	if (!ASSERT_OK_PTR(skel, "bpf_smc__open_and_load"))
		return;

	ret = bpf_smc__attach(skel);
	ASSERT_EQ(ret, 0, "bpf_smc__attach");

	bpf_smc__destroy(skel);
}

void test_bpf_smc(void)
{
	if (test__start_subtest("load"))
		load();
}
