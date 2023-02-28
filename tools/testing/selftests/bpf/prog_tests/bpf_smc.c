// SPDX-License-Identifier: GPL-2.0

#include <linux/err.h>
#include <netinet/tcp.h>
#include <test_progs.h>
#include "bpf_smc.skel.h"

void test_bpf_smc(void)
{
	struct bpf_smc *smc_skel;
	struct bpf_link *link;
	int err;

	smc_skel = bpf_smc__open();
	if (!ASSERT_OK_PTR(smc_skel, "skel_open"))
		return;

	err = bpf_map__set_type(smc_skel->maps.negotiator_map, BPF_MAP_TYPE_HASH);
	if (!ASSERT_OK(err, "bpf_map__set_type"))
		goto error;

	err = bpf_map__set_max_entries(smc_skel->maps.negotiator_map, 1);
	if (!ASSERT_OK(err, "bpf_map__set_type"))
		goto error;

	err =  bpf_smc__load(smc_skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto error;

	link = bpf_map__attach_struct_ops(smc_skel->maps.ops);
	if (!ASSERT_OK_PTR(link, "bpf_map__attach_struct_ops"))
		goto error;

	bpf_link__destroy(link);
error:
	bpf_smc__destroy(smc_skel);
}
