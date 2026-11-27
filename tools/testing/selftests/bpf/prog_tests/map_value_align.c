// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>
#include "map_value_align.skel.h"

#define IFINDEX_LO 1

/* The verifier assumes that map values are 8-byte aligned */
void test_map_value_align(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
	);
	struct bpf_devmap_val dval = { .ifindex = IFINDEX_LO };
	struct { __u32 prefixlen, data; } lkey = { .prefixlen = 32 };
	struct map_value_align *skel;
	__u64 val = 0;
	__u32 key = 0;
	int err;

	skel = map_value_align__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	err = bpf_map__update_elem(skel->maps.lpm, &lkey, sizeof(lkey),
				   &val, sizeof(val), BPF_ANY);
	if (!ASSERT_OK(err, "lpm_update"))
		goto out;
	err = bpf_map__update_elem(skel->maps.hash, &key, sizeof(key),
				   &val, sizeof(val), BPF_ANY);
	if (!ASSERT_OK(err, "hash_update"))
		goto out;
	err = bpf_map__update_elem(skel->maps.devmap, &key, sizeof(key),
				   &dval, sizeof(dval), BPF_ANY);
	if (!ASSERT_OK(err, "devmap_update"))
		goto out;

	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.lookup), &topts);
	if (!ASSERT_OK(err, "test_run"))
		goto out;

	ASSERT_NEQ(skel->bss->lpm_addr, 0, "lpm_lookup");
	ASSERT_EQ(skel->bss->lpm_addr & 7, 0, "lpm_value_align");
	ASSERT_NEQ(skel->bss->hash_addr, 0, "hash_lookup");
	ASSERT_EQ(skel->bss->hash_addr & 7, 0, "hash_value_align");
	ASSERT_NEQ(skel->bss->devmap_addr, 0, "devmap_lookup");
	ASSERT_EQ(skel->bss->devmap_addr & 7, 0, "devmap_value_align");
out:
	map_value_align__destroy(skel);
}
