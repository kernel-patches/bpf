// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>
#include <net/if.h>
#include "test_xdp_do_redirect.skel.h"

#define SYS(fmt, ...)						\
	({							\
		char cmd[1024];					\
		snprintf(cmd, sizeof(cmd), fmt, ##__VA_ARGS__);	\
		if (!ASSERT_OK(system(cmd), cmd))		\
			goto fail;				\
	})

#define NUM_PKTS 10
void test_xdp_do_redirect(void)
{
	struct test_xdp_do_redirect *skel = NULL;
	struct ipv6_packet data = pkt_v6;
	struct xdp_md ctx_in = { .data_end = sizeof(data) };
	__u8 dst_mac[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
	__u8 src_mac[ETH_ALEN] = {0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb};
	DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts,
			    .data_in = &data,
			    .data_size_in = sizeof(data),
			    .ctx_in = &ctx_in,
			    .ctx_size_in = sizeof(ctx_in),
			    .flags = BPF_F_TEST_XDP_DO_REDIRECT,
			    .repeat = NUM_PKTS,
		);
	int err, prog_fd, ifindex_src, ifindex_dst;
	struct bpf_link *link;

	memcpy(data.eth.h_dest, dst_mac, ETH_ALEN);
	memcpy(data.eth.h_source, src_mac, ETH_ALEN);

	skel = test_xdp_do_redirect__open();
	if (!ASSERT_OK_PTR(skel, "skel"))
		return;

	SYS("ip link add veth_src type veth peer name veth_dst");
	SYS("ip link set dev veth_src up");
	SYS("ip link set dev veth_dst up");

	ifindex_src = if_nametoindex("veth_src");
	ifindex_dst = if_nametoindex("veth_dst");
	if (!ASSERT_NEQ(ifindex_src, 0, "ifindex_src") ||
	    !ASSERT_NEQ(ifindex_dst, 0, "ifindex_dst"))
		goto fail;

	memcpy(skel->rodata->expect_dst, dst_mac, ETH_ALEN);
	skel->rodata->ifindex_out = ifindex_src;

	if (!ASSERT_OK(test_xdp_do_redirect__load(skel), "load"))
		goto fail;

	link = bpf_program__attach_xdp(skel->progs.xdp_count_pkts, ifindex_dst);
	if (!ASSERT_OK_PTR(link, "prog_attach"))
		goto fail;
	skel->links.xdp_count_pkts = link;

	prog_fd = bpf_program__fd(skel->progs.xdp_redirect_notouch);
	err = bpf_prog_test_run_opts(prog_fd, &opts);
	if (!ASSERT_OK(err, "prog_run"))
		goto fail;

	/* wait for the packets to be flushed */
	kern_sync_rcu();

	ASSERT_EQ(skel->bss->pkts_seen, NUM_PKTS, "pkt_count");
fail:
	system("ip link del dev veth_src");
	test_xdp_do_redirect__destroy(skel);
}
