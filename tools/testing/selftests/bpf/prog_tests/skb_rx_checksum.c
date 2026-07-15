// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>
#include "skb_rx_checksum.skel.h"
#include "skb_rx_checksum.h"

#define TX_PACKETS 3

static int run_test(__u32 flags, enum skb_csum expected_csum)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = TX_PACKETS,
		.flags = flags,
	);
	int prog_fd, err, key = expected_csum;
	struct skb_rx_checksum *skel;
	__u64 cnt;

	skel = skb_rx_checksum__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return -1;

	prog_fd = bpf_program__fd(skel->progs.tc_rx_csum);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	if (!ASSERT_OK(err, "test_run"))
		goto cleanup;

	if (!ASSERT_EQ(topts.retval, 0, "retval"))
		goto cleanup;

	err = bpf_map_lookup_elem(bpf_map__fd(skel->maps.csum_cnt), &key, &cnt);
	if (!ASSERT_OK(err, "map_lookup"))
		goto cleanup;

	ASSERT_EQ(cnt, TX_PACKETS, "csum_cnt");
cleanup:
	skb_rx_checksum__destroy(skel);
	return 0;
}

void test_skb_rx_checksum(void)
{
	if (test__start_subtest("csum_none"))
		run_test(0, SKB_CSUM_NONE);

	if (test__start_subtest("csum_complete"))
		run_test(BPF_F_TEST_SKB_CHECKSUM_COMPLETE, SKB_CSUM_COMPLETE);
}
