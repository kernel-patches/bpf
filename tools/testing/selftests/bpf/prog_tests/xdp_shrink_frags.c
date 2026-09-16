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

#define NS_NAME_MAX_LEN	32
#define VETH_LOCAL	"xdp_shrinkA"
#define VETH_PEER	"xdp_shrinkB"
#define VETH_LOCAL_IP	"10.9.9.1"
#define VETH_PEER_IP	"10.9.9.2"
#define VETH_LOCAL_MAC	"02:00:00:00:00:01"

/*
 * skb_pp_cow_data() keeps up to one page in the linear part, so the packet
 * sizes below only leave a frag (smaller than the 3000-byte shrink, so it is
 * released as a whole) on 4K pages. Skip elsewhere rather than run a test
 * that cannot tell a fixed kernel from a buggy one.
 */
#define PAGE_SIZE_4K	4096

/*
 * Generous, so a loaded CI does not fail the assert prematurely; normally
 * the first check already succeeds.
 */
#define WAIT_ITERS	10000
#define WAIT_US		1000

static void wait_for_prog(struct xdp_shrink_frags *skel)
{
	int i;

	for (i = 0; i < WAIT_ITERS && !skel->bss->shrink_ran; i++)
		usleep(WAIT_US);
}

static int create_tap_napi_frags(const char *ifname)
{
	struct ifreq ifr = {
		.ifr_flags = IFF_TAP | IFF_NO_PI | IFF_NAPI | IFF_NAPI_FRAGS,
	};
	int fd, err;

	strscpy(ifr.ifr_name, ifname);

	fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0)
		return -errno;

	err = ioctl(fd, TUNSETIFF, &ifr);
	if (err) {
		err = -errno;
		close(fd);
		return err;
	}

	return fd;
}

/*
 * Similar to flow_dissector.c: writev() an IFF_NAPI_FRAGS tap to build a
 * nonlinear skb that tun runs through do_xdp_generic().
 */
static void test_tun(struct xdp_shrink_frags *skel)
{
	__u8 head[74], frag1[2048], frag2[2048];
	struct ethhdr *eth = (void *)head;
	int tap_fd = -1, ifindex, err;
	struct netns_obj *ns = NULL;
	struct iovec iov[3];
	ssize_t n;

	if (getpagesize() != PAGE_SIZE_4K) {
		test__skip();
		return;
	}

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

	wait_for_prog(skel);
	/* a buggy kernel only splats "page_pool leak", it does not fail here */
	ASSERT_GT(skel->bss->shrink_ran, 0, "xdp_prog_ran");

	bpf_xdp_detach(ifindex, 0, NULL);
out:
	if (tap_fd >= 0)
		close(tap_fd);
	netns_free(ns);
}

/*
 * Both veth ends live in their own namespace, so the traffic really crosses
 * the pair and nothing is created in the caller's namespace.
 */
static int veth_setup(char *ns0, char *ns1)
{
	if (!ASSERT_OK(append_tid(ns0, NS_NAME_MAX_LEN), "append_tid ns0"))
		return -1;
	if (!ASSERT_OK(append_tid(ns1, NS_NAME_MAX_LEN), "append_tid ns1"))
		return -1;

	SYS(fail, "ip netns add %s", ns0);
	SYS(fail_ns0, "ip netns add %s", ns1);
	SYS(fail_ns1, "ip -n %s link add %s mtu 8000 type veth peer name %s mtu 8000",
	    ns0, VETH_LOCAL, VETH_PEER);
	SYS(fail_ns1, "ip -n %s link set %s netns %s", ns0, VETH_PEER, ns1);
	SYS(fail_ns1, "ip -n %s link set %s address %s", ns0, VETH_LOCAL,
	    VETH_LOCAL_MAC);
	SYS(fail_ns1, "ip -n %s addr add %s/24 dev %s", ns0, VETH_LOCAL_IP,
	    VETH_LOCAL);
	SYS(fail_ns1, "ip -n %s link set %s up", ns0, VETH_LOCAL);
	SYS(fail_ns1, "ip -n %s addr add %s/24 dev %s", ns1, VETH_PEER_IP,
	    VETH_PEER);
	SYS(fail_ns1, "ip -n %s link set %s up", ns1, VETH_PEER);

	return 0;

fail_ns1:
	SYS_NOFAIL("ip netns del %s", ns1);
fail_ns0:
	SYS_NOFAIL("ip netns del %s", ns0);
fail:
	return -1;
}

static void veth_cleanup(const char *ns0, const char *ns1)
{
	/* Dropping the namespaces takes the veth pair and its XDP programs. */
	SYS_NOFAIL("ip netns del %s", ns1);
	SYS_NOFAIL("ip netns del %s", ns0);
}

static int veth_attach(const char *ns, const char *dev, int prog_fd)
{
	struct nstoken *nstoken;
	int ifindex, err;

	nstoken = open_netns(ns);
	if (!ASSERT_OK_PTR(nstoken, "open_netns"))
		return -1;

	ifindex = if_nametoindex(dev);
	if (!ASSERT_GT(ifindex, 0, "if_nametoindex")) {
		close_netns(nstoken);
		return -1;
	}

	err = bpf_xdp_attach(ifindex, prog_fd, 0, NULL);
	close_netns(nstoken);

	return ASSERT_OK(err, "bpf_xdp_attach") ? 0 : -1;
}

/* A large ping builds a nonlinear skb that veth cow's into its page_pool. */
static void test_veth(struct xdp_shrink_frags *skel)
{
	char ns0[NS_NAME_MAX_LEN] = "xdp_shrink_ns0-";
	char ns1[NS_NAME_MAX_LEN] = "xdp_shrink_ns1-";

	if (getpagesize() != PAGE_SIZE_4K) {
		test__skip();
		return;
	}

	if (veth_setup(ns0, ns1))
		return;

	skel->bss->shrink_ran = 0;

	if (veth_attach(ns0, VETH_LOCAL, bpf_program__fd(skel->progs.xdp_shrink)))
		goto out;

	SYS_NOFAIL("ip netns exec %s ping -q -s 5000 -c 3 -W 1 %s",
		   ns1, VETH_LOCAL_IP);

	wait_for_prog(skel);
	/* a buggy kernel only splats "page_pool leak", it does not fail here */
	ASSERT_GT(skel->bss->shrink_ran, 0, "xdp_prog_ran");
out:
	veth_cleanup(ns0, ns1);
}

/*
 * LOCAL cow's the incoming skb and returns XDP_TX, so the buff is turned into
 * an xdp_frame and bounced to PEER, which shrinks a frag. A page_pool tag
 * recorded on the buff must not leak into the frame, or PEER frees a plain
 * page (whose pp was already cleared on the XDP_TX side) as page_pool memory.
 */
static void test_veth_tx(struct xdp_shrink_frags *skel)
{
	char ns0[NS_NAME_MAX_LEN] = "xdp_shrink_tx0-";
	char ns1[NS_NAME_MAX_LEN] = "xdp_shrink_tx1-";

	if (getpagesize() != PAGE_SIZE_4K) {
		test__skip();
		return;
	}

	if (veth_setup(ns0, ns1))
		return;

	/*
	 * LOCAL bounces everything (incl. ARP) with XDP_TX, so pin a static
	 * neighbour to let the ping's payload actually reach it.
	 */
	SYS(out, "ip -n %s neigh add %s lladdr %s dev %s nud permanent",
	    ns1, VETH_LOCAL_IP, VETH_LOCAL_MAC, VETH_PEER);

	skel->bss->shrink_ran = 0;

	if (veth_attach(ns0, VETH_LOCAL, bpf_program__fd(skel->progs.xdp_tx)))
		goto out;
	if (veth_attach(ns1, VETH_PEER, bpf_program__fd(skel->progs.xdp_shrink)))
		goto out;

	SYS_NOFAIL("ip netns exec %s ping -q -s 5000 -c 3 -W 1 %s",
		   ns1, VETH_LOCAL_IP);

	wait_for_prog(skel);
	/* a buggy kernel only splats "page_pool leak", it does not fail here */
	ASSERT_GT(skel->bss->shrink_ran, 0, "xdp_prog_ran");
out:
	veth_cleanup(ns0, ns1);
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
	if (test__start_subtest("veth_tx"))
		test_veth_tx(skel);

	xdp_shrink_frags__destroy(skel);
}
