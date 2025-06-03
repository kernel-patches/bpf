// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>
#include <bpf/btf.h>
#include <linux/if_link.h>

#include "xdp_rxmeta_redirect.skel.h"
#include "xdp_rxmeta_receiver.skel.h"

#define LOCAL_NETNS_NAME	"local"
#define FWD_NETNS_NAME		"forward"
#define DST_NETNS_NAME		"dest"

#define LOCAL_NAME	"local"
#define FWD0_NAME	"fwd0"
#define FWD1_NAME	"fwd1"
#define DST_NAME	"dest"

#define LOCAL_MAC	"00:00:00:00:00:01"
#define FWD0_MAC	"00:00:00:00:00:02"
#define FWD1_MAC	"00:00:00:00:01:01"
#define DST_MAC		"00:00:00:00:01:02"

#define LOCAL_ADDR	"10.0.0.1"
#define FWD0_ADDR	"10.0.0.2"
#define FWD1_ADDR	"20.0.0.1"
#define DST_ADDR	"20.0.0.2"

#define PREFIX_LEN	"8"
#define NUM_PACKETS	10

static int run_ping(const char *dst, int num_ping)
{
	SYS(fail, "ping -c%d -W1 -i0.5 %s >/dev/null", num_ping, dst);
	return 0;
fail:
	return -1;
}

void test_xdp_rxmeta(void)
{
	struct xdp_rxmeta_redirect *skel_redirect = NULL;
	struct xdp_rxmeta_receiver *skel_receiver = NULL;
	struct bpf_devmap_val val = {};
	struct bpf_program *prog;
	__u32 key = 0, stats;
	struct nstoken *tok;
	int ret, index;

	SYS(out, "ip netns add " LOCAL_NETNS_NAME);
	SYS(out, "ip netns add " FWD_NETNS_NAME);
	SYS(out, "ip netns add " DST_NETNS_NAME);

	tok = open_netns(LOCAL_NETNS_NAME);
	if (!ASSERT_OK_PTR(tok, "setns"))
		goto out;

	SYS(out, "ip link add " LOCAL_NAME " type veth peer " FWD0_NAME);
	SYS(out, "ip link set " FWD0_NAME " netns " FWD_NETNS_NAME);
	SYS(out, "ip link set dev " LOCAL_NAME " address " LOCAL_MAC);
	SYS(out, "ip addr add " LOCAL_ADDR "/" PREFIX_LEN " dev " LOCAL_NAME);
	SYS(out, "ip link set dev " LOCAL_NAME " up");
	SYS(out, "ip route add default via " FWD0_ADDR);
	close_netns(tok);

	tok = open_netns(DST_NETNS_NAME);
	if (!ASSERT_OK_PTR(tok, "setns"))
		goto out;

	SYS(out, "ip link add " DST_NAME " type veth peer " FWD1_NAME);
	SYS(out, "ip link set " FWD1_NAME " netns " FWD_NETNS_NAME);
	SYS(out, "ip link set dev " DST_NAME " address " DST_MAC);
	SYS(out, "ip addr add " DST_ADDR "/" PREFIX_LEN " dev " DST_NAME);
	SYS(out, "ip link set dev " DST_NAME " up");
	SYS(out, "ip route add default via " FWD1_ADDR);

	skel_receiver = xdp_rxmeta_receiver__open();
	if (!ASSERT_OK_PTR(skel_receiver, "open skel_receiver"))
		goto out;

	prog = bpf_object__find_program_by_name(skel_receiver->obj,
						"xdp_rxmeta_receiver");
	index = if_nametoindex(DST_NAME);
	bpf_program__set_ifindex(prog, index);
	bpf_program__set_flags(prog, BPF_F_XDP_DEV_BOUND_ONLY);

	if (!ASSERT_OK(xdp_rxmeta_receiver__load(skel_receiver),
		       "load skel_receiver"))
		goto out;

	ret = bpf_xdp_attach(index,
			     bpf_program__fd(skel_receiver->progs.xdp_rxmeta_receiver),
			     XDP_FLAGS_DRV_MODE, NULL);
	if (!ASSERT_GE(ret, 0, "bpf_xdp_attach rx_meta_redirect"))
		goto out;

	close_netns(tok);
	tok = open_netns(FWD_NETNS_NAME);
	if (!ASSERT_OK_PTR(tok, "setns"))
		goto out;

	SYS(out, "ip link set dev " FWD0_NAME " address " FWD0_MAC);
	SYS(out, "ip addr add " FWD0_ADDR "/" PREFIX_LEN " dev " FWD0_NAME);
	SYS(out, "ip link set dev " FWD0_NAME " up");

	SYS(out, "ip link set dev " FWD1_NAME " address " FWD1_MAC);
	SYS(out, "ip addr add " FWD1_ADDR "/" PREFIX_LEN " dev " FWD1_NAME);
	SYS(out, "ip link set dev " FWD1_NAME " up");

	SYS(out, "sysctl -qw net.ipv4.conf.all.forwarding=1");

	skel_redirect = xdp_rxmeta_redirect__open();
	if (!ASSERT_OK_PTR(skel_redirect, "open skel_redirect"))
		goto out;

	prog = bpf_object__find_program_by_name(skel_redirect->obj,
						"xdp_rxmeta_redirect");
	index = if_nametoindex(FWD0_NAME);
	bpf_program__set_ifindex(prog, index);
	bpf_program__set_flags(prog, BPF_F_XDP_DEV_BOUND_ONLY);

	if (!ASSERT_OK(xdp_rxmeta_redirect__load(skel_redirect),
		       "load skel_redirect"))
		goto out;

	val.ifindex = if_nametoindex(FWD1_NAME);
	ret = bpf_map_update_elem(bpf_map__fd(skel_redirect->maps.dev_map),
				  &key, &val, 0);
	if (!ASSERT_GE(ret, 0, "bpf_map_update_elem"))
		goto out;

	ret = bpf_xdp_attach(index,
			     bpf_program__fd(skel_redirect->progs.xdp_rxmeta_redirect),
			     XDP_FLAGS_DRV_MODE, NULL);
	if (!ASSERT_GE(ret, 0, "bpf_xdp_attach rxmeta_redirect"))
		goto out;

	close_netns(tok);
	tok = open_netns(LOCAL_NETNS_NAME);
	if (!ASSERT_OK_PTR(tok, "setns"))
		goto out;

	if (!ASSERT_OK(run_ping(DST_ADDR, NUM_PACKETS), "ping"))
		goto out;

	close_netns(tok);
	tok = open_netns(DST_NETNS_NAME);
	if (!ASSERT_OK_PTR(tok, "setns"))
		goto out;

	ret = bpf_map__lookup_elem(skel_receiver->maps.stats,
				   &key, sizeof(key),
				   &stats, sizeof(stats), 0);
	if (!ASSERT_GE(ret, 0, "bpf_map_update_elem"))
		goto out;

	ASSERT_EQ(stats, NUM_PACKETS, "rx_meta stats");
out:
	xdp_rxmeta_redirect__destroy(skel_redirect);
	xdp_rxmeta_receiver__destroy(skel_receiver);
	if (tok)
		close_netns(tok);
	SYS_NOFAIL("ip netns del " LOCAL_NETNS_NAME);
	SYS_NOFAIL("ip netns del " FWD_NETNS_NAME);
	SYS_NOFAIL("ip netns del " DST_NETNS_NAME);
}
