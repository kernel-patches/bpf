// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>
#include <linux/ipv6.h>
#include <arpa/inet.h>
#include "test_xdp_context_test_run.skel.h"
#include "test_xdp_meta.skel.h"

#define RX_NAME "veth0"
#define TX_NAME "veth1"
#define TX_NETNS "xdp_context_tx"
#define RX_NETNS "xdp_context_rx"
#define SKB_TRACE_RX_NAME "skb_trace_veth0"
#define SKB_TRACE_TX_NAME "skb_trace_veth1"
#define SKB_TRACE_TX_NETNS "skb_trace_tx"
#define SKB_TRACE_RX_NETNS "skb_trace_rx"
#define RX_MAC "02:00:00:00:00:01"
#define TX_MAC "02:00:00:00:00:02"
#define TAP_NAME "tap0"
#define DUMMY_NAME "dum0"
#define TAP_NETNS "xdp_context_tuntap"
#define LWT_NETNS "xdp_context_lwt"
#define SKB_TRACE_NETNS "skb_trace_tuntap"

#define TEST_PAYLOAD_LEN 32
static const __u8 test_payload[TEST_PAYLOAD_LEN] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
};

void test_xdp_context_error(int prog_fd, struct bpf_test_run_opts opts,
			    __u32 data_meta, __u32 data, __u32 data_end,
			    __u32 ingress_ifindex, __u32 rx_queue_index,
			    __u32 egress_ifindex)
{
	struct xdp_md ctx = {
		.data = data,
		.data_end = data_end,
		.data_meta = data_meta,
		.ingress_ifindex = ingress_ifindex,
		.rx_queue_index = rx_queue_index,
		.egress_ifindex = egress_ifindex,
	};
	int err;

	opts.ctx_in = &ctx;
	opts.ctx_size_in = sizeof(ctx);
	err = bpf_prog_test_run_opts(prog_fd, &opts);
	ASSERT_EQ(errno, EINVAL, "errno-EINVAL");
	ASSERT_ERR(err, "bpf_prog_test_run");
}

void test_xdp_context_test_run(void)
{
	struct test_xdp_context_test_run *skel = NULL;
	char data[sizeof(pkt_v4) + sizeof(__u32)];
	char bad_ctx[sizeof(struct xdp_md) + 1];
	char large_data[256];
	struct xdp_md ctx_in, ctx_out;
	DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts,
			    .data_in = &data,
			    .data_size_in = sizeof(data),
			    .ctx_out = &ctx_out,
			    .ctx_size_out = sizeof(ctx_out),
			    .repeat = 1,
		);
	int err, prog_fd;

	skel = test_xdp_context_test_run__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel"))
		return;
	prog_fd = bpf_program__fd(skel->progs.xdp_context);

	/* Data past the end of the kernel's struct xdp_md must be 0 */
	bad_ctx[sizeof(bad_ctx) - 1] = 1;
	opts.ctx_in = bad_ctx;
	opts.ctx_size_in = sizeof(bad_ctx);
	err = bpf_prog_test_run_opts(prog_fd, &opts);
	ASSERT_EQ(errno, E2BIG, "extradata-errno");
	ASSERT_ERR(err, "bpf_prog_test_run(extradata)");

	*(__u32 *)data = XDP_PASS;
	*(struct ipv4_packet *)(data + sizeof(__u32)) = pkt_v4;
	opts.ctx_in = &ctx_in;
	opts.ctx_size_in = sizeof(ctx_in);
	memset(&ctx_in, 0, sizeof(ctx_in));
	ctx_in.data_meta = 0;
	ctx_in.data = sizeof(__u32);
	ctx_in.data_end = ctx_in.data + sizeof(pkt_v4);
	err = bpf_prog_test_run_opts(prog_fd, &opts);
	ASSERT_OK(err, "bpf_prog_test_run(valid)");
	ASSERT_EQ(opts.retval, XDP_PASS, "valid-retval");
	ASSERT_EQ(opts.data_size_out, sizeof(pkt_v4), "valid-datasize");
	ASSERT_EQ(opts.ctx_size_out, opts.ctx_size_in, "valid-ctxsize");
	ASSERT_EQ(ctx_out.data_meta, 0, "valid-datameta");
	ASSERT_EQ(ctx_out.data, 0, "valid-data");
	ASSERT_EQ(ctx_out.data_end, sizeof(pkt_v4), "valid-dataend");

	/* Meta data's size must be a multiple of 4 */
	test_xdp_context_error(prog_fd, opts, 0, 1, sizeof(data), 0, 0, 0);

	/* data_meta must reference the start of data */
	test_xdp_context_error(prog_fd, opts, 4, sizeof(__u32), sizeof(data),
			       0, 0, 0);

	/* Total size of data must be data_end - data_meta or larger */
	test_xdp_context_error(prog_fd, opts, 0, sizeof(__u32),
			       sizeof(data) + 1, 0, 0, 0);

	/* RX queue cannot be specified without specifying an ingress */
	test_xdp_context_error(prog_fd, opts, 0, sizeof(__u32), sizeof(data),
			       0, 1, 0);

	/* Interface 1 is always the loopback interface which always has only
	 * one RX queue (index 0). This makes index 1 an invalid rx queue index
	 * for interface 1.
	 */
	test_xdp_context_error(prog_fd, opts, 0, sizeof(__u32), sizeof(data),
			       1, 1, 0);

	/* The egress cannot be specified */
	test_xdp_context_error(prog_fd, opts, 0, sizeof(__u32), sizeof(data),
			       0, 0, 1);

	/* Meta data must be 216 bytes or smaller (256 - sizeof(struct
	 * xdp_frame)). Test both nearest invalid size and nearest invalid
	 * 4-byte-aligned size, and make sure data_in is large enough that we
	 * actually hit the check on metadata length
	 */
	opts.data_in = large_data;
	opts.data_size_in = sizeof(large_data);
	test_xdp_context_error(prog_fd, opts, 0, 217, sizeof(large_data), 0, 0, 0);
	test_xdp_context_error(prog_fd, opts, 0, 220, sizeof(large_data), 0, 0, 0);

	test_xdp_context_test_run__destroy(skel);
}

static int send_test_packet(int ifindex)
{
	int n, sock = -1;
	__u8 packet[sizeof(struct ethhdr) + TEST_PAYLOAD_LEN];

	/* We use the Ethernet header only to identify the test packet */
	struct ethhdr eth = {
		.h_source = { 0x12, 0x34, 0xDE, 0xAD, 0xBE, 0xEF },
	};

	memcpy(packet, &eth, sizeof(eth));
	memcpy(packet + sizeof(eth), test_payload, TEST_PAYLOAD_LEN);

	sock = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
	if (!ASSERT_GE(sock, 0, "socket"))
		goto err;

	struct sockaddr_ll saddr = {
		.sll_family = PF_PACKET,
		.sll_ifindex = ifindex,
		.sll_halen = ETH_ALEN
	};
	n = sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&saddr,
		   sizeof(saddr));
	if (!ASSERT_EQ(n, sizeof(packet), "sendto"))
		goto err;

	close(sock);
	return 0;

err:
	if (sock >= 0)
		close(sock);
	return -1;
}

static int write_test_packet(int tap_fd)
{
	__u8 packet[sizeof(struct ethhdr) + TEST_PAYLOAD_LEN];
	int n;

	/* The Ethernet header is mostly not relevant. We use it to identify the
	 * test packet and some BPF helpers we exercise expect to operate on
	 * Ethernet frames carrying IP packets. Pretend that's the case.
	 */
	struct ethhdr eth = {
		.h_source = { 0x12, 0x34, 0xDE, 0xAD, 0xBE, 0xEF },
		.h_proto = htons(ETH_P_IP),
	};

	memcpy(packet, &eth, sizeof(eth));
	memcpy(packet + sizeof(struct ethhdr), test_payload, TEST_PAYLOAD_LEN);

	n = write(tap_fd, packet, sizeof(packet));
	if (!ASSERT_EQ(n, sizeof(packet), "write packet"))
		return -1;

	return 0;
}

/* Inject Ethernet+IPv6+UDP frame into TAP */
static int write_test_packet_udp(int tap_fd)
{
	__u8 pkt[sizeof(struct ethhdr) + sizeof(struct ipv6hdr) +
		 sizeof(struct udphdr) + TEST_PAYLOAD_LEN] = {};
	struct ethhdr *eth = (void *)pkt;
	struct ipv6hdr *ip6 = (void *)(eth + 1);
	struct udphdr *udp = (void *)(ip6 + 1);
	__u8 *payload = (void *)(udp + 1);
	const __u8 tap_mac[ETH_ALEN] = { 0x02, 0, 0, 0, 0, 0x01 };
	int n;

	memcpy(eth->h_dest, tap_mac, ETH_ALEN);
	eth->h_proto = htons(ETH_P_IPV6);

	ip6->version = 6;
	ip6->hop_limit = 64;
	ip6->nexthdr = IPPROTO_UDP;
	ip6->payload_len = htons(sizeof(*udp) + TEST_PAYLOAD_LEN);
	inet_pton(AF_INET6, "fd00::2", &ip6->saddr);
	inet_pton(AF_INET6, "fd00:1::1", &ip6->daddr);

	udp->source = htons(42);
	udp->dest = htons(42);
	udp->len = htons(sizeof(*udp) + TEST_PAYLOAD_LEN);
	/* UDP checksum is not validated on the forwarding path. */

	memcpy(payload, test_payload, TEST_PAYLOAD_LEN);

	n = write(tap_fd, pkt, sizeof(pkt));
	if (!ASSERT_EQ(n, sizeof(pkt), "write frame"))
		return -1;

	return 0;
}

static void dump_err_stream(const struct bpf_program *prog)
{
	char buf[512];
	int ret;

	ret = 0;
	do {
		ret = bpf_prog_stream_read(bpf_program__fd(prog),
					   BPF_STREAM_STDERR, buf, sizeof(buf),
					   NULL);
		if (ret > 0)
			fwrite(buf, sizeof(buf[0]), ret, stderr);
	} while (ret > 0);
}

void test_xdp_context_veth(void)
{
	LIBBPF_OPTS(bpf_tc_hook, tc_hook, .attach_point = BPF_TC_INGRESS);
	LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = 1, .priority = 1);
	struct netns_obj *rx_ns = NULL, *tx_ns = NULL;
	struct bpf_program *tc_prog, *xdp_prog;
	struct test_xdp_meta *skel = NULL;
	struct nstoken *nstoken = NULL;
	int rx_ifindex, tx_ifindex;
	int ret;

	tx_ns = netns_new(TX_NETNS, false);
	if (!ASSERT_OK_PTR(tx_ns, "create tx_ns"))
		return;

	rx_ns = netns_new(RX_NETNS, false);
	if (!ASSERT_OK_PTR(rx_ns, "create rx_ns"))
		goto close;

	SYS(close, "ip link add " RX_NAME " netns " RX_NETNS
	    " type veth peer name " TX_NAME " netns " TX_NETNS);

	nstoken = open_netns(RX_NETNS);
	if (!ASSERT_OK_PTR(nstoken, "setns rx_ns"))
		goto close;

	SYS(close, "ip link set dev " RX_NAME " up");

	skel = test_xdp_meta__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open and load skeleton"))
		goto close;

	rx_ifindex = if_nametoindex(RX_NAME);
	if (!ASSERT_GE(rx_ifindex, 0, "if_nametoindex rx"))
		goto close;

	tc_hook.ifindex = rx_ifindex;
	ret = bpf_tc_hook_create(&tc_hook);
	if (!ASSERT_OK(ret, "bpf_tc_hook_create"))
		goto close;

	tc_prog = bpf_object__find_program_by_name(skel->obj, "ing_cls");
	if (!ASSERT_OK_PTR(tc_prog, "open ing_cls prog"))
		goto close;

	tc_opts.prog_fd = bpf_program__fd(tc_prog);
	ret = bpf_tc_attach(&tc_hook, &tc_opts);
	if (!ASSERT_OK(ret, "bpf_tc_attach"))
		goto close;

	xdp_prog = bpf_object__find_program_by_name(skel->obj, "ing_xdp");
	if (!ASSERT_OK_PTR(xdp_prog, "open ing_xdp prog"))
		goto close;

	ret = bpf_xdp_attach(rx_ifindex,
			     bpf_program__fd(xdp_prog),
			     0, NULL);
	if (!ASSERT_GE(ret, 0, "bpf_xdp_attach"))
		goto close;

	close_netns(nstoken);

	nstoken = open_netns(TX_NETNS);
	if (!ASSERT_OK_PTR(nstoken, "setns tx_ns"))
		goto close;

	SYS(close, "ip link set dev " TX_NAME " up");

	tx_ifindex = if_nametoindex(TX_NAME);
	if (!ASSERT_GE(tx_ifindex, 0, "if_nametoindex tx"))
		goto close;

	skel->bss->test_pass = false;

	ret = send_test_packet(tx_ifindex);
	if (!ASSERT_OK(ret, "send_test_packet"))
		goto close;

	if (!ASSERT_TRUE(skel->bss->test_pass, "test_pass"))
		dump_err_stream(tc_prog);

close:
	close_netns(nstoken);
	test_xdp_meta__destroy(skel);
	netns_free(rx_ns);
	netns_free(tx_ns);
}

static void __test_tuntap(const char *nsname,
			  struct bpf_program *xdp_prog,
			  struct bpf_program *tc_prio_1_prog,
			  struct bpf_program *tc_prio_2_prog,
			  bool *test_pass)
{
	LIBBPF_OPTS(bpf_tc_hook, tc_hook, .attach_point = BPF_TC_INGRESS);
	LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = 1, .priority = 1);
	struct netns_obj *ns = NULL;
	int tap_fd = -1;
	int tap_ifindex;
	int ret;

	*test_pass = false;

	ns = netns_new(nsname, true);
	if (!ASSERT_OK_PTR(ns, "create and open ns"))
		return;

	tap_fd = open_tuntap(TAP_NAME, true);
	if (!ASSERT_GE(tap_fd, 0, "open_tuntap"))
		goto close;

	SYS(close, "ip link set dev " TAP_NAME " up");

	tap_ifindex = if_nametoindex(TAP_NAME);
	if (!ASSERT_GE(tap_ifindex, 0, "if_nametoindex"))
		goto close;

	tc_hook.ifindex = tap_ifindex;
	ret = bpf_tc_hook_create(&tc_hook);
	if (!ASSERT_OK(ret, "bpf_tc_hook_create"))
		goto close;

	tc_opts.prog_fd = bpf_program__fd(tc_prio_1_prog);
	ret = bpf_tc_attach(&tc_hook, &tc_opts);
	if (!ASSERT_OK(ret, "bpf_tc_attach"))
		goto close;

	if (tc_prio_2_prog) {
		LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = 1, .priority = 2,
			    .prog_fd = bpf_program__fd(tc_prio_2_prog));

		ret = bpf_tc_attach(&tc_hook, &tc_opts);
		if (!ASSERT_OK(ret, "bpf_tc_attach"))
			goto close;
	}

	ret = bpf_xdp_attach(tap_ifindex, bpf_program__fd(xdp_prog),
			     0, NULL);
	if (!ASSERT_GE(ret, 0, "bpf_xdp_attach"))
		goto close;

	ret = write_test_packet(tap_fd);
	if (!ASSERT_OK(ret, "write_test_packet"))
		goto close;

	if (!ASSERT_TRUE(*test_pass, "test_pass"))
		dump_err_stream(tc_prio_2_prog ? : tc_prio_1_prog);

close:
	if (tap_fd >= 0)
		close(tap_fd);
	netns_free(ns);
}

static void test_tuntap(struct bpf_program *xdp_prog,
			struct bpf_program *tc_prio_1_prog,
			struct bpf_program *tc_prio_2_prog,
			bool *test_pass)
{
	__test_tuntap(TAP_NETNS, xdp_prog, tc_prio_1_prog, tc_prio_2_prog,
		      test_pass);
}

/* Write a packet to a tap dev and copy it to ingress of a dummy dev */
static void test_tuntap_mirred(struct bpf_program *xdp_prog,
			       struct bpf_program *tc_prog,
			       bool *test_pass)
{
	LIBBPF_OPTS(bpf_tc_hook, tc_hook, .attach_point = BPF_TC_INGRESS);
	LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = 1, .priority = 1);
	struct netns_obj *ns = NULL;
	int dummy_ifindex;
	int tap_fd = -1;
	int tap_ifindex;
	int ret;

	*test_pass = false;

	ns = netns_new(TAP_NETNS, true);
	if (!ASSERT_OK_PTR(ns, "netns_new"))
		return;

	/* Setup dummy interface */
	SYS(close, "ip link add name " DUMMY_NAME " type dummy");
	SYS(close, "ip link set dev " DUMMY_NAME " up");

	dummy_ifindex = if_nametoindex(DUMMY_NAME);
	if (!ASSERT_GE(dummy_ifindex, 0, "if_nametoindex"))
		goto close;

	tc_hook.ifindex = dummy_ifindex;
	ret = bpf_tc_hook_create(&tc_hook);
	if (!ASSERT_OK(ret, "bpf_tc_hook_create"))
		goto close;

	tc_opts.prog_fd = bpf_program__fd(tc_prog);
	ret = bpf_tc_attach(&tc_hook, &tc_opts);
	if (!ASSERT_OK(ret, "bpf_tc_attach"))
		goto close;

	/* Setup TAP interface */
	tap_fd = open_tuntap(TAP_NAME, true);
	if (!ASSERT_GE(tap_fd, 0, "open_tuntap"))
		goto close;

	SYS(close, "ip link set dev " TAP_NAME " up");

	tap_ifindex = if_nametoindex(TAP_NAME);
	if (!ASSERT_GE(tap_ifindex, 0, "if_nametoindex"))
		goto close;

	ret = bpf_xdp_attach(tap_ifindex, bpf_program__fd(xdp_prog), 0, NULL);
	if (!ASSERT_GE(ret, 0, "bpf_xdp_attach"))
		goto close;

	/* Copy all packets received from TAP to dummy ingress */
	SYS(close, "tc qdisc add dev " TAP_NAME " clsact");
	SYS(close, "tc filter add dev " TAP_NAME " ingress "
		   "protocol all matchall "
		   "action mirred ingress mirror dev " DUMMY_NAME);

	/* Receive a packet on TAP */
	ret = write_test_packet(tap_fd);
	if (!ASSERT_OK(ret, "write_test_packet"))
		goto close;

	if (!ASSERT_TRUE(*test_pass, "test_pass"))
		dump_err_stream(tc_prog);

close:
	if (tap_fd >= 0)
		close(tap_fd);
	netns_free(ns);
}

void test_xdp_context_tuntap(void)
{
	struct test_xdp_meta *skel = NULL;

	skel = test_xdp_meta__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open and load skeleton"))
		return;

	if (test__start_subtest("data_meta"))
		test_tuntap(skel->progs.ing_xdp,
			    skel->progs.ing_cls,
			    NULL, /* tc prio 2 */
			    &skel->bss->test_pass);
	if (test__start_subtest("dynptr_read"))
		test_tuntap(skel->progs.ing_xdp,
			    skel->progs.ing_cls_dynptr_read,
			    NULL, /* tc prio 2 */
			    &skel->bss->test_pass);
	if (test__start_subtest("dynptr_slice"))
		test_tuntap(skel->progs.ing_xdp,
			    skel->progs.ing_cls_dynptr_slice,
			    NULL, /* tc prio 2 */
			    &skel->bss->test_pass);
	if (test__start_subtest("dynptr_write"))
		test_tuntap(skel->progs.ing_xdp_zalloc_meta,
			    skel->progs.ing_cls_dynptr_write,
			    skel->progs.ing_cls_dynptr_read,
			    &skel->bss->test_pass);
	if (test__start_subtest("dynptr_slice_rdwr"))
		test_tuntap(skel->progs.ing_xdp_zalloc_meta,
			    skel->progs.ing_cls_dynptr_slice_rdwr,
			    skel->progs.ing_cls_dynptr_slice,
			    &skel->bss->test_pass);
	if (test__start_subtest("dynptr_offset"))
		test_tuntap(skel->progs.ing_xdp_zalloc_meta,
			    skel->progs.ing_cls_dynptr_offset_wr,
			    skel->progs.ing_cls_dynptr_offset_rd,
			    &skel->bss->test_pass);
	if (test__start_subtest("dynptr_offset_oob"))
		test_tuntap(skel->progs.ing_xdp,
			    skel->progs.ing_cls_dynptr_offset_oob,
			    skel->progs.ing_cls,
			    &skel->bss->test_pass);
	if (test__start_subtest("clone_data_meta_survives_data_write"))
		test_tuntap_mirred(skel->progs.ing_xdp,
				   skel->progs.clone_data_meta_survives_data_write,
				   &skel->bss->test_pass);
	if (test__start_subtest("clone_data_meta_survives_meta_write"))
		test_tuntap_mirred(skel->progs.ing_xdp,
				   skel->progs.clone_data_meta_survives_meta_write,
				   &skel->bss->test_pass);
	if (test__start_subtest("clone_meta_dynptr_survives_data_slice_write"))
		test_tuntap_mirred(skel->progs.ing_xdp,
				   skel->progs.clone_meta_dynptr_survives_data_slice_write,
				   &skel->bss->test_pass);
	if (test__start_subtest("clone_meta_dynptr_survives_meta_slice_write"))
		test_tuntap_mirred(skel->progs.ing_xdp,
				   skel->progs.clone_meta_dynptr_survives_meta_slice_write,
				   &skel->bss->test_pass);
	if (test__start_subtest("clone_meta_dynptr_rw_before_data_dynptr_write"))
		test_tuntap_mirred(skel->progs.ing_xdp,
				   skel->progs.clone_meta_dynptr_rw_before_data_dynptr_write,
				   &skel->bss->test_pass);
	if (test__start_subtest("clone_meta_dynptr_rw_before_meta_dynptr_write"))
		test_tuntap_mirred(skel->progs.ing_xdp,
				   skel->progs.clone_meta_dynptr_rw_before_meta_dynptr_write,
				   &skel->bss->test_pass);
	/* Tests for BPF helpers which touch headroom */
	if (test__start_subtest("helper_skb_vlan_push_pop"))
		test_tuntap(skel->progs.ing_xdp,
			    skel->progs.helper_skb_vlan_push_pop,
			    NULL, /* tc prio 2 */
			    &skel->bss->test_pass);
	if (test__start_subtest("helper_skb_adjust_room"))
		test_tuntap(skel->progs.ing_xdp,
			    skel->progs.helper_skb_adjust_room,
			    NULL, /* tc prio 2 */
			    &skel->bss->test_pass);
	if (test__start_subtest("helper_skb_change_head_tail"))
		test_tuntap(skel->progs.ing_xdp,
			    skel->progs.helper_skb_change_head_tail,
			    NULL, /* tc prio 2 */
			    &skel->bss->test_pass);
	if (test__start_subtest("helper_skb_change_proto"))
		test_tuntap(skel->progs.ing_xdp,
			    skel->progs.helper_skb_change_proto,
			    NULL, /* tc prio 2 */
			    &skel->bss->test_pass);

	test_xdp_meta__destroy(skel);
}

/*
 * Test topology:
 *
 *	tap0 fd00::1
 *	  RX:  injected IPv6 UDP frame, XDP ingress sets metadata
 *	  fwd: encap route prepends outer header(s)
 *	  TX:  TC egress validates metadata
 *
 * A routable IPv6 UDP frame is written into the tap fd, so it enters the RX
 * path where XDP stores metadata. Routing then forwards it back out the same
 * tap through an encapsulating route that prepends outer header(s). The TC
 * egress program checks that the pushed header did not silently corrupt
 * metadata.
 */
#define LWT_PIN_PATH "/sys/fs/bpf/xdp_context_lwt_xmit"

enum lwt_encap_type {
	LWT_ENCAP_BPF,
	LWT_ENCAP_MPLS,
	LWT_ENCAP_SEG6,
	LWT_ENCAP_IOAM6,
};

static void test_lwt_encap(struct test_xdp_meta *skel,
			   enum lwt_encap_type type)
{
	LIBBPF_OPTS(bpf_tc_hook, tc_hook, .attach_point = BPF_TC_EGRESS);
	LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = 1, .priority = 1);
	struct bpf_program *lwt_prog = NULL;
	struct netns_obj *ns = NULL;
	const char *encap;
	bool pinned = false;
	int tap_ifindex;
	int tap_fd = -1;
	int ret;

	skel->bss->test_pass = false;

	switch (type) {
	case LWT_ENCAP_BPF:
		encap = "encap bpf xmit pinned " LWT_PIN_PATH " via fd00::2";
		lwt_prog = skel->progs.dummy_lwt_xmit;
		break;
	case LWT_ENCAP_MPLS:
		encap = "encap mpls 100 via inet6 fd00::2";
		break;
	case LWT_ENCAP_SEG6:
		encap = "encap seg6 mode encap segs fd00::2";
		break;
	case LWT_ENCAP_IOAM6:
		encap = "encap ioam6 mode encap tundst fd00::2 "
			"trace prealloc type 0x800000 ns 0 size 4 via fd00::2";
		break;
	default:
		return;
	}

	if (lwt_prog) {
		unlink(LWT_PIN_PATH);
		ret = bpf_program__pin(lwt_prog, LWT_PIN_PATH);
		if (!ASSERT_OK(ret, "pin lwt prog"))
			return;
		pinned = true;
	}

	ns = netns_new(LWT_NETNS, true);
	if (!ASSERT_OK_PTR(ns, "netns_new"))
		goto close;

	tap_fd = open_tuntap(TAP_NAME, true);
	if (!ASSERT_GE(tap_fd, 0, "open_tuntap"))
		goto close;

	SYS(close, "ip link set dev " TAP_NAME " address " RX_MAC);
	SYS(close, "sysctl -wq net.ipv6.conf.all.forwarding=1");
	SYS(close, "ip addr add fd00::1/64 dev " TAP_NAME " nodad");
	SYS(close, "ip link set dev " TAP_NAME " up");
	SYS(close, "ip neigh add fd00::2 lladdr " TX_MAC " nud permanent dev " TAP_NAME);
	SYS(close, "ip -6 route add fd00:1::/64 %s dev %s", encap, TAP_NAME);

	tap_ifindex = if_nametoindex(TAP_NAME);
	if (!ASSERT_GE(tap_ifindex, 0, "if_nametoindex"))
		goto close;

	ret = bpf_xdp_attach(tap_ifindex, bpf_program__fd(skel->progs.ing_xdp),
			     0, NULL);
	if (!ASSERT_GE(ret, 0, "bpf_xdp_attach"))
		goto close;

	tc_hook.ifindex = tap_ifindex;
	ret = bpf_tc_hook_create(&tc_hook);
	if (!ASSERT_OK(ret, "bpf_tc_hook_create"))
		goto close;

	tc_opts.prog_fd = bpf_program__fd(skel->progs.tc_is_meta_empty);
	ret = bpf_tc_attach(&tc_hook, &tc_opts);
	if (!ASSERT_OK(ret, "bpf_tc_attach"))
		goto close;

	ret = write_test_packet_udp(tap_fd);
	if (!ASSERT_OK(ret, "write_test_packet_udp"))
		goto close;

	if (!ASSERT_TRUE(skel->bss->test_pass, "test_pass"))
		dump_err_stream(skel->progs.tc_is_meta_empty);

close:
	if (tap_fd >= 0)
		close(tap_fd);
	netns_free(ns);
	if (pinned)
		unlink(LWT_PIN_PATH);
}

void test_xdp_context_lwt_encap(void)
{
	struct test_xdp_meta *skel;

	skel = test_xdp_meta__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open and load skeleton"))
		return;

	if (test__start_subtest("bpf_encap"))
		test_lwt_encap(skel, LWT_ENCAP_BPF);
	if (test__start_subtest("mpls_encap"))
		test_lwt_encap(skel, LWT_ENCAP_MPLS);
	if (test__start_subtest("seg6_encap"))
		test_lwt_encap(skel, LWT_ENCAP_SEG6);
	if (test__start_subtest("ioam6_encap"))
		test_lwt_encap(skel, LWT_ENCAP_IOAM6);

	test_xdp_meta__destroy(skel);
}

static bool is_map_empty(struct bpf_map *map)
{
	void *key;

	return bpf_map_get_next_key(bpf_map__fd(map), NULL, &key) &&
	       errno == ENOENT;
}

static void test_skb_trace__tuntap(struct test_xdp_meta *skel)
{
	struct bpf_link *link;

	skel->bss->free_count = 0;

	link = bpf_program__attach(skel->progs.skb_free);
	if (!ASSERT_OK_PTR(link, "prog_attach"))
		return;

	__test_tuntap(SKB_TRACE_NETNS, NULL /* xdp */, skel->progs.tc_meta_write,
		      skel->progs.tc_meta_read, &skel->bss->test_pass);

	ASSERT_GE(skel->bss->free_count, 1, "free_count");
	ASSERT_TRUE(is_map_empty(skel->maps.meta_map), "stash drained");

	bpf_link__destroy(link);
}

/*
 * Test if stashed metadata survives skb clone (via tc mirred).
 * tap_prog writes on the tap ingress, dummy_prog runs on the clone
 * (dummy ingress).
 */
static void test_skb_trace__mirred_clone(struct test_xdp_meta *skel)
{
	LIBBPF_OPTS(bpf_tc_hook, tc_hook, .attach_point = BPF_TC_INGRESS);
	LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = 1, .priority = 1);
	struct bpf_link *put_link = NULL, *copy_link = NULL;
	struct netns_obj *ns = NULL;
	int dummy_ifindex;
	int tap_ifindex;
	int tap_fd = -1;
	int ret;

	skel->bss->write_done = false;
	skel->bss->test_pass = false;
	skel->bss->free_count = 0;
	skel->bss->copy_done = false;

	put_link = bpf_program__attach(skel->progs.skb_free);
	if (!ASSERT_OK_PTR(put_link, "put_attach"))
		return;

	copy_link = bpf_program__attach(skel->progs.skb_copy);
	if (!ASSERT_OK_PTR(copy_link, "copy_attach"))
		goto close;

	ns = netns_new("mirred_clone", true);
	if (!ASSERT_OK_PTR(ns, "netns_new"))
		goto close;

	/* Dummy dev: attach reader */
	SYS(close, "ip link add name " DUMMY_NAME " type dummy");
	SYS(close, "ip link set dev " DUMMY_NAME " up");

	dummy_ifindex = if_nametoindex(DUMMY_NAME);
	if (!ASSERT_GT(dummy_ifindex, 0, "dummy_ifindex"))
		goto close;

	tc_hook.ifindex = dummy_ifindex;
	ret = bpf_tc_hook_create(&tc_hook);
	if (!ASSERT_OK(ret, "dummy_hook_create"))
		goto close;

	tc_opts.prog_fd = bpf_program__fd(skel->progs.tc_meta_read);
	ret = bpf_tc_attach(&tc_hook, &tc_opts);
	if (!ASSERT_OK(ret, "dummy_attach"))
		goto close;

	/* TAP dev: attach writer + mirred to dummy */
	tap_fd = open_tuntap(TAP_NAME, true);
	if (!ASSERT_GE(tap_fd, 0, "open_tuntap"))
		goto close;

	SYS(close, "ip link set dev " TAP_NAME " up");

	tap_ifindex = if_nametoindex(TAP_NAME);
	if (!ASSERT_GT(tap_ifindex, 0, "tap_ifindex"))
		goto close;

	tc_hook.ifindex = tap_ifindex;
	ret = bpf_tc_hook_create(&tc_hook);
	if (!ASSERT_OK(ret, "tap_hook_create"))
		goto close;

	tc_opts.prog_id = 0;
	tc_opts.prog_fd = bpf_program__fd(skel->progs.tc_meta_write);
	ret = bpf_tc_attach(&tc_hook, &tc_opts);
	if (!ASSERT_OK(ret, "tap_attach"))
		goto close;

	SYS(close, "tc filter add dev " TAP_NAME " ingress "
		   "protocol all matchall "
		   "action mirred ingress mirror dev " DUMMY_NAME);

	ret = write_test_packet(tap_fd);
	if (!ASSERT_OK(ret, "write_test_packet"))
		goto close;

	ASSERT_TRUE(skel->bss->write_done, "write_done");
	ASSERT_TRUE(skel->bss->test_pass, "test_pass");
	ASSERT_TRUE(skel->bss->copy_done, "copy_done");
	ASSERT_GE(skel->bss->free_count, 2, "free_count");
	ASSERT_TRUE(is_map_empty(skel->maps.meta_map), "stash drained");

close:
	bpf_link__destroy(copy_link);
	bpf_link__destroy(put_link);
	if (tap_fd >= 0)
		close(tap_fd);
	netns_free(ns);
}

/* Test if skb_ext survives veth cross-netns forward */
static void test_skb_trace__veth(struct test_xdp_meta *skel)
{
	LIBBPF_OPTS(bpf_tc_hook, tx_hook, .attach_point = BPF_TC_EGRESS);
	LIBBPF_OPTS(bpf_tc_opts, tx_opts, .handle = 1, .priority = 1);
	LIBBPF_OPTS(bpf_tc_hook, rx_hook, .attach_point = BPF_TC_INGRESS);
	LIBBPF_OPTS(bpf_tc_opts, rx_opts, .handle = 1, .priority = 1);
	struct netns_obj *rx_ns = NULL, *tx_ns = NULL;
	struct bpf_link *put_link = NULL;
	struct nstoken *nstoken = NULL;
	int rx_ifindex, tx_ifindex;
	int ret;
	int i;

	put_link = bpf_program__attach(skel->progs.skb_free);
	if (!ASSERT_OK_PTR(put_link, "put_attach"))
		return;

	tx_ns = netns_new(SKB_TRACE_TX_NETNS, false);
	if (!ASSERT_OK_PTR(tx_ns, "create tx_ns"))
		goto close;

	rx_ns = netns_new(SKB_TRACE_RX_NETNS, false);
	if (!ASSERT_OK_PTR(rx_ns, "create rx_ns"))
		goto close;

	SYS(close, "ip link add " SKB_TRACE_RX_NAME " netns " SKB_TRACE_RX_NETNS
	    " type veth peer name " SKB_TRACE_TX_NAME " netns " SKB_TRACE_TX_NETNS);

	/* Setup RX side: TC ingress reader */
	nstoken = open_netns(SKB_TRACE_RX_NETNS);
	if (!ASSERT_OK_PTR(nstoken, "setns rx_ns"))
		goto close;

	SYS(close, "ip link set dev " SKB_TRACE_RX_NAME " up");

	rx_ifindex = if_nametoindex(SKB_TRACE_RX_NAME);
	if (!ASSERT_GT(rx_ifindex, 0, "if_nametoindex rx"))
		goto close;

	rx_hook.ifindex = rx_ifindex;
	ret = bpf_tc_hook_create(&rx_hook);
	if (!ASSERT_OK(ret, "bpf_tc_hook_create rx"))
		goto close;

	rx_opts.prog_fd = bpf_program__fd(skel->progs.tc_meta_read);
	ret = bpf_tc_attach(&rx_hook, &rx_opts);
	if (!ASSERT_OK(ret, "bpf_tc_attach rx"))
		goto close;

	close_netns(nstoken);

	/* Setup TX side: TC egress writer */
	nstoken = open_netns(SKB_TRACE_TX_NETNS);
	if (!ASSERT_OK_PTR(nstoken, "setns tx_ns"))
		goto close;

	SYS(close, "ip link set dev " SKB_TRACE_TX_NAME " up");

	tx_ifindex = if_nametoindex(SKB_TRACE_TX_NAME);
	if (!ASSERT_GT(tx_ifindex, 0, "if_nametoindex tx"))
		goto close;

	tx_hook.ifindex = tx_ifindex;
	ret = bpf_tc_hook_create(&tx_hook);
	if (!ASSERT_OK(ret, "bpf_tc_hook_create tx"))
		goto close;

	tx_opts.prog_fd = bpf_program__fd(skel->progs.tc_meta_write);
	ret = bpf_tc_attach(&tx_hook, &tx_opts);
	if (!ASSERT_OK(ret, "bpf_tc_attach tx"))
		goto close;

	skel->bss->test_pass = false;
	skel->bss->free_count = 0;

	ret = send_test_packet(tx_ifindex);
	if (!ASSERT_OK(ret, "send_test_packet"))
		goto close;

	/* Poll every 10 msec up to 1 sec */
	for (i = 0; i < 100 && !skel->bss->test_pass; i++)
		usleep(10000);
	ASSERT_TRUE(skel->bss->test_pass, "test_pass");

	/* Wait for the free tp to drain all tagged skbs from the stash */
	for (i = 0; i < 100 && !is_map_empty(skel->maps.meta_map); i++)
		usleep(10000);
	ASSERT_TRUE(is_map_empty(skel->maps.meta_map), "stash drained");
	ASSERT_GE(skel->bss->free_count, 1, "free_count");

close:
	bpf_link__destroy(put_link);
	close_netns(nstoken);
	netns_free(rx_ns);
	netns_free(tx_ns);
}

/* Test if skb_ext survives GRE tunnel encap+decap */
static void test_skb_trace__gre(struct test_xdp_meta *skel)
{
	LIBBPF_OPTS(bpf_tc_hook, tx_hook, .attach_point = BPF_TC_EGRESS);
	LIBBPF_OPTS(bpf_tc_opts, tx_opts, .handle = 1, .priority = 1);
	LIBBPF_OPTS(bpf_tc_hook, rx_hook, .attach_point = BPF_TC_INGRESS);
	LIBBPF_OPTS(bpf_tc_opts, rx_opts, .handle = 1, .priority = 1);
	struct bpf_link *put_link = NULL;
	struct netns_obj *ns = NULL;
	int tx_ifindex;
	int rx_ifindex;
	int ret;
	int i;

	put_link = bpf_program__attach(skel->progs.skb_free);
	if (!ASSERT_OK_PTR(put_link, "put_attach"))
		return;

	ns = netns_new("gre_test", true);
	if (!ASSERT_OK_PTR(ns, "netns_new"))
		goto close;

	/* Setup: gre_tx -> lo -> gre_rx */
	SYS(close, "ip link set lo up");
	SYS(close, "ip link add gre_tx type gretap"
	    " local 127.0.0.1 remote 127.0.0.2");
	SYS(close, "ip link set gre_tx up");
	SYS(close, "ip addr add 127.0.0.2/8 dev lo");
	SYS(close, "ip link add gre_rx type gretap"
	    " local 127.0.0.2 remote 127.0.0.1");
	SYS(close, "ip link set gre_rx up");

	/* Write skb_ext on TC egress on GRE tx */
	tx_ifindex = if_nametoindex("gre_tx");
	if (!ASSERT_GT(tx_ifindex, 0, "tx_ifindex"))
		goto close;

	tx_hook.ifindex = tx_ifindex;
	ret = bpf_tc_hook_create(&tx_hook);
	if (!ASSERT_OK(ret, "tx_hook_create"))
		goto close;

	tx_opts.prog_fd = bpf_program__fd(skel->progs.tc_meta_write);
	ret = bpf_tc_attach(&tx_hook, &tx_opts);
	if (!ASSERT_OK(ret, "tx_attach"))
		goto close;

	/* Read skb_ext on TC ingress on GRE rx */
	rx_ifindex = if_nametoindex("gre_rx");
	if (!ASSERT_GT(rx_ifindex, 0, "rx_ifindex"))
		goto close;

	rx_hook.ifindex = rx_ifindex;
	ret = bpf_tc_hook_create(&rx_hook);
	if (!ASSERT_OK(ret, "rx_hook_create"))
		goto close;

	rx_opts.prog_fd = bpf_program__fd(skel->progs.tc_meta_read);
	ret = bpf_tc_attach(&rx_hook, &rx_opts);
	if (!ASSERT_OK(ret, "rx_attach"))
		goto close;

	/* Then use send_test_packet on GRE tx */
	skel->bss->test_pass = false;
	skel->bss->free_count = 0;

	ret = send_test_packet(tx_ifindex);
	if (!ASSERT_OK(ret, "send_test_packet"))
		goto close;

	/* Poll every 10 msec up to 1 sec */
	for (i = 0; i < 100 && !skel->bss->test_pass; i++)
		usleep(10000);
	ASSERT_TRUE(skel->bss->test_pass, "test_pass");

	/* Wait for the free tp to drain all tagged skbs from the stash */
	for (i = 0; i < 100 && !is_map_empty(skel->maps.meta_map); i++)
		usleep(10000);
	ASSERT_TRUE(is_map_empty(skel->maps.meta_map), "stash drained");
	ASSERT_GE(skel->bss->free_count, 1, "free_count");

close:
	bpf_link__destroy(put_link);
	netns_free(ns);
}

void test_skb_trace_basic(void)
{
	struct test_xdp_meta *skel = NULL;

	skel = test_xdp_meta__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open and load skeleton"))
		return;

	if (test__start_subtest("write_read"))
		test_skb_trace__tuntap(skel);
	if (test__start_subtest("clone_read"))
		test_skb_trace__mirred_clone(skel);
	if (test__start_subtest("survives_veth"))
		test_skb_trace__veth(skel);
	if (test__start_subtest("survives_gre"))
		test_skb_trace__gre(skel);

	test_xdp_meta__destroy(skel);
}
