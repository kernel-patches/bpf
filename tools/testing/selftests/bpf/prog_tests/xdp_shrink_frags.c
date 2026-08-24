// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>
#include <linux/if_tun.h>
#include <linux/if_ether.h>
#include <sys/uio.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "xdp_shrink_frags.skel.h"

/*
 * A generic-XDP program that shrinks into the frags frees a page_pool frag.
 * skb-backed XDP first cow's the nonlinear skb into page_pool memory
 * (skb_cow_data_for_xdp() for generic XDP, skb_pp_cow_data() for veth), but
 * the shared rxq is registered as MEM_TYPE_PAGE_SHARED, so a buggy kernel
 * frees the frag with page_frag_free() -> "Bad page state ... page_pool leak".
 */

#define TAP_NAME	"xdp_shrink0"
#define TAP_NETNS	"xdp_shrink_tap"

#define VETH_LOCAL	"xdp_shrinkA"
#define VETH_PEER	"xdp_shrinkB"
#define VETH_NETNS	"xdp_shrink_veth"
#define VETH_LOCAL_IP	"10.9.9.1"
#define VETH_PEER_IP	"10.9.9.2"

static int create_tap_napi_frags(const char *ifname)
{
	struct ifreq ifr = {
		.ifr_flags = IFF_TAP | IFF_NO_PI | IFF_NAPI | IFF_NAPI_FRAGS,
	};
	int fd, err;

	strscpy(ifr.ifr_name, ifname);

	fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0)
		return -1;

	err = ioctl(fd, TUNSETIFF, &ifr);
	if (err) {
		close(fd);
		return -1;
	}

	return fd;
}

/*
 * Similar to flow_dissector.c: writev() an IFF_NAPI_FRAGS tap to build a
 * nonlinear skb (sized for 4K pages, like xdp_adjust_tail.c) that tun runs
 * through do_xdp_generic().
 */
static void test_tun(struct xdp_shrink_frags *skel)
{
	__u8 head[74], frag1[2048], frag2[2048];
	struct ethhdr *eth = (void *)head;
	int tap_fd = -1, ifindex, err;
	struct netns_obj *ns = NULL;
	struct iovec iov[3];
	ssize_t n;

	ns = netns_new(TAP_NETNS, true);
	if (!ASSERT_OK_PTR(ns, "netns_new"))
		return;

	tap_fd = create_tap_napi_frags(TAP_NAME);
	if (!ASSERT_GE(tap_fd, 0, "create_tap"))
		goto out;

	SYS(out, "ip link set dev " TAP_NAME " up");

	ifindex = if_nametoindex(TAP_NAME);
	if (!ASSERT_GT(ifindex, 0, "if_nametoindex"))
		goto out;

	skel->bss->shrink_ran = 0;

	err = bpf_xdp_attach(ifindex, bpf_program__fd(skel->progs.xdp_shrink),
			     0, NULL);
	if (!ASSERT_OK(err, "bpf_xdp_attach"))
		goto out;

	memset(head, 0, sizeof(head));
	memset(frag1, 0x41, sizeof(frag1));
	memset(frag2, 0x42, sizeof(frag2));
	eth->h_proto = htons(ETH_P_IP);

	iov[0].iov_base = head;  iov[0].iov_len = sizeof(head);
	iov[1].iov_base = frag1; iov[1].iov_len = sizeof(frag1);
	iov[2].iov_base = frag2; iov[2].iov_len = sizeof(frag2);

	n = writev(tap_fd, iov, ARRAY_SIZE(iov));
	ASSERT_EQ(n, sizeof(head) + sizeof(frag1) + sizeof(frag2), "writev");

	usleep(100 * 1000);
	ASSERT_GT(skel->bss->shrink_ran, 0, "xdp_prog_ran");

	bpf_xdp_detach(ifindex, 0, NULL);
out:
	if (tap_fd >= 0)
		close(tap_fd);
	netns_free(ns);
}

/*
 * A large ping builds a nonlinear skb that veth cow's into its page_pool
 * (sized for 4K pages, like xdp_adjust_tail.c) before running the program.
 */
static void test_veth(struct xdp_shrink_frags *skel)
{
	int ifindex, err;

	SYS(out, "ip netns add " VETH_NETNS);
	SYS(out_ns, "ip link add %s mtu 8000 type veth peer name %s mtu 8000",
	    VETH_LOCAL, VETH_PEER);
	SYS(out_link, "ip link set " VETH_PEER " netns " VETH_NETNS);
	SYS(out_link, "ip addr add " VETH_LOCAL_IP "/24 dev " VETH_LOCAL);
	SYS(out_link, "ip link set " VETH_LOCAL " up");
	SYS(out_link, "ip -n " VETH_NETNS " addr add " VETH_PEER_IP "/24 dev " VETH_PEER);
	SYS(out_link, "ip -n " VETH_NETNS " link set " VETH_PEER " up");

	ifindex = if_nametoindex(VETH_LOCAL);
	if (!ASSERT_GT(ifindex, 0, "if_nametoindex"))
		goto out_link;

	skel->bss->shrink_ran = 0;

	err = bpf_xdp_attach(ifindex, bpf_program__fd(skel->progs.xdp_shrink),
			     0, NULL);
	if (!ASSERT_OK(err, "bpf_xdp_attach"))
		goto out_link;

	SYS_NOFAIL("ip netns exec " VETH_NETNS
		   " ping -q -s 5000 -c 3 -W 1 " VETH_LOCAL_IP);

	ASSERT_GT(skel->bss->shrink_ran, 0, "xdp_prog_ran");

	bpf_xdp_detach(ifindex, 0, NULL);
out_link:
	SYS_NOFAIL("ip link del " VETH_LOCAL);
out_ns:
	SYS_NOFAIL("ip netns del " VETH_NETNS);
out:
	return;
}

void test_xdp_shrink_frags(void)
{
	struct xdp_shrink_frags *skel;

	skel = xdp_shrink_frags__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_load"))
		return;

	if (test__start_subtest("tun"))
		test_tun(skel);
	if (test__start_subtest("veth"))
		test_veth(skel);

	xdp_shrink_frags__destroy(skel);
}
