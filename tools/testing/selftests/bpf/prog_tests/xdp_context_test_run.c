// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>
#include "test_xdp_context_test_run.skel.h"
#include "test_xdp_meta.skel.h"

#define RX_NAME "veth0"
#define TX_NAME "veth1"
#define TX_NETNS "xdp_context_tx"
#define RX_NETNS "xdp_context_rx"
#define RX_MAC "02:00:00:00:00:01"
#define TX_MAC "02:00:00:00:00:02"
#define TAP_NAME "tap0"
#define DUMMY_NAME "dum0"
#define TAP_NETNS "xdp_context_tuntap"
#define ENCAP_DEV "encap"
#define DECAP_RX_NETNS "xdp_context_decap_rx"
#define DECAP_TX_NETNS "xdp_context_decap_tx"

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

	/* Meta data must be 255 bytes or smaller */
	test_xdp_context_error(prog_fd, opts, 0, 256, sizeof(data), 0, 0, 0);

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

	test_xdp_context_test_run__destroy(skel);
}

static int send_test_packet(int ifindex)
{
	int n, sock = -1;
	__u8 packet[sizeof(struct ethhdr) + TEST_PAYLOAD_LEN];

	/* We use the Ethernet header only to identify the test packet */
	struct ethhdr eth = {
		.h_source = { 0x12, 0x34, 0xDE, 0xAD, 0xBE, 0xEF },
		.h_proto = htons(ETH_P_IP),
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

static int send_routed_packet(int af, const char *ip)
{
	struct sockaddr_storage addr;
	socklen_t alen;
	int r, sock = -1;

	r = make_sockaddr(af, ip, 42, &addr, &alen);
	if (!ASSERT_OK(r, "make_sockaddr"))
		goto err;

	sock = socket(af, SOCK_DGRAM, 0);
	if (!ASSERT_OK_FD(sock, "socket"))
		goto err;

	r = sendto(sock, test_payload, sizeof(test_payload), 0,
		   (struct sockaddr *)&addr, alen);
	if (!ASSERT_EQ(r, sizeof(test_payload), "sendto"))
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

static void test_tuntap(struct bpf_program *xdp_prog,
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

	ns = netns_new(TAP_NETNS, true);
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

enum l2_encap_type {
	GRE4_ENCAP,
	GRE6_ENCAP,
	VXLAN_ENCAP,
	GENEVE_ENCAP,
	L2TPV3_ENCAP,
	VLAN_ENCAP,
	QINQ_ENCAP,
	MPLS_ENCAP,
};

static bool l2_encap_uses_ipv6(enum l2_encap_type encap_type)
{
	return encap_type == GRE6_ENCAP;
}

static bool l2_encap_uses_routing(enum l2_encap_type encap_type)
{
	return encap_type == MPLS_ENCAP;
}

static bool setup_l2_encap_dev(enum l2_encap_type encap_type,
			       const char *encap_dev, const char *lower_dev,
			       const char *net_prefix, const char *local_addr,
			       const char *remote_addr)
{
	switch (encap_type) {
	case GRE4_ENCAP:
		SYS(fail, "ip link add %s type gretap local %s remote %s",
		    encap_dev, local_addr, remote_addr);
		return true;

	case GRE6_ENCAP:
		SYS(fail, "ip link add %s type ip6gretap local %s remote %s",
		    encap_dev, local_addr, remote_addr);
		return true;

	case VXLAN_ENCAP:
		SYS(fail,
		    "ip link add %s type vxlan id 42 local %s remote %s dstport 4789",
		    encap_dev, local_addr, remote_addr);
		return true;

	case GENEVE_ENCAP:
		SYS(fail,
		    "ip link add %s type geneve id 42 remote %s",
		    encap_dev, remote_addr);
		return true;

	case L2TPV3_ENCAP:
		SYS(fail,
		    "ip l2tp add tunnel tunnel_id 42 peer_tunnel_id 42 encap ip local %s remote %s",
		    local_addr, remote_addr);
		SYS(fail,
		    "ip l2tp add session name %s tunnel_id 42 session_id 42 peer_session_id 42",
		    encap_dev);
		return true;

	case VLAN_ENCAP:
		SYS(fail, "ip link set dev %s down", lower_dev);
		SYS(fail, "ethtool -K %s rx-vlan-hw-parse off", lower_dev);
		SYS(fail, "ethtool -K %s tx-vlan-hw-insert off", lower_dev);
		SYS(fail, "ip link set dev %s up", lower_dev);
		SYS(fail, "ip link add %s link %s type vlan id 42", encap_dev,
		    lower_dev);
		return true;

	case QINQ_ENCAP:
		SYS(fail, "ip link set dev %s down", lower_dev);
		SYS(fail, "ethtool -K %s rx-vlan-hw-parse off", lower_dev);
		SYS(fail, "ethtool -K %s tx-vlan-hw-insert off", lower_dev);
		SYS(fail, "ethtool -K %s rx-vlan-stag-hw-parse off", lower_dev);
		SYS(fail, "ethtool -K %s tx-vlan-stag-hw-insert off", lower_dev);
		SYS(fail, "ip link set dev %s up", lower_dev);
		SYS(fail, "ip link add vlan.100 link %s type vlan proto 802.1ad id 100", lower_dev);
		SYS(fail, "ip link set dev vlan.100 up");
		SYS(fail, "ip link add %s link vlan.100 type vlan id 42", encap_dev);
		return true;

	case MPLS_ENCAP:
		SYS(fail, "sysctl -wq net.mpls.platform_labels=65535");
		SYS(fail, "sysctl -wq net.mpls.conf.%s.input=1", lower_dev);
		SYS(fail, "ip route change %s encap mpls 42 via %s", net_prefix, remote_addr);
		SYS(fail, "ip -f mpls route add 42 dev lo");
		SYS(fail, "ip link set dev lo name %s", encap_dev);

		return true;
	}
fail:
	return false;
}

static void test_l2_decap(enum l2_encap_type encap_type,
			  struct bpf_program *xdp_prog,
			  struct bpf_program *tc_prog, bool *test_pass)
{
	LIBBPF_OPTS(bpf_tc_hook, tc_hook, .attach_point = BPF_TC_INGRESS);
	LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = 1, .priority = 1);
	const char *net, *rx_ip, *tx_ip, *addr_opts;
	int af, plen;
	struct netns_obj *rx_ns = NULL, *tx_ns = NULL;
	struct nstoken *nstoken = NULL;
	int lower_ifindex, upper_ifindex;
	int ret;

	if (l2_encap_uses_ipv6(encap_type)) {
		af = AF_INET6;
		net = "fd00::/64";
		rx_ip = "fd00::1";
		tx_ip = "fd00::2";
		plen = 64;
		addr_opts = "nodad";
	} else {
		af = AF_INET;
		net = "192.0.2.0/24";
		rx_ip = "192.0.2.1";
		tx_ip = "192.0.2.2";
		plen = 24;
		addr_opts = "";
	}

	*test_pass = false;

	rx_ns = netns_new(DECAP_RX_NETNS, false);
	if (!ASSERT_OK_PTR(rx_ns, "create rx_ns"))
		return;

	tx_ns = netns_new(DECAP_TX_NETNS, false);
	if (!ASSERT_OK_PTR(tx_ns, "create tx_ns"))
		goto close;

	SYS(close, "ip link add " RX_NAME " address " RX_MAC " netns " DECAP_RX_NETNS
		   " type veth peer name " TX_NAME " address " TX_MAC " netns " DECAP_TX_NETNS);

	nstoken = open_netns(DECAP_RX_NETNS);
	if (!ASSERT_OK_PTR(nstoken, "setns rx_ns"))
		goto close;

	SYS(close, "ip addr add %s/%u dev %s %s", rx_ip, plen, RX_NAME, addr_opts);
	SYS(close, "ip link set dev %s up", RX_NAME);

	if (!setup_l2_encap_dev(encap_type, ENCAP_DEV, RX_NAME, net, rx_ip, tx_ip))
		goto close;
	SYS(close, "ip link set dev %s up", ENCAP_DEV);

	lower_ifindex = if_nametoindex(RX_NAME);
	if (!ASSERT_GE(lower_ifindex, 0, "if_nametoindex lower"))
		goto close;

	upper_ifindex = if_nametoindex(ENCAP_DEV);
	if (!ASSERT_GE(upper_ifindex, 0, "if_nametoindex upper"))
		goto close;

	ret = bpf_xdp_attach(lower_ifindex, bpf_program__fd(xdp_prog), 0, NULL);
	if (!ASSERT_GE(ret, 0, "bpf_xdp_attach"))
		goto close;

	tc_hook.ifindex = upper_ifindex;
	ret = bpf_tc_hook_create(&tc_hook);
	if (!ASSERT_OK(ret, "bpf_tc_hook_create"))
		goto close;

	tc_opts.prog_fd = bpf_program__fd(tc_prog);
	ret = bpf_tc_attach(&tc_hook, &tc_opts);
	if (!ASSERT_OK(ret, "bpf_tc_attach"))
		goto close;

	close_netns(nstoken);

	nstoken = open_netns(DECAP_TX_NETNS);
	if (!ASSERT_OK_PTR(nstoken, "setns tx_ns"))
		goto close;

	SYS(close, "ip addr add %s/%u dev %s %s", tx_ip, plen, TX_NAME, addr_opts);
	SYS(close, "ip neigh add %s lladdr %s nud permanent dev %s", rx_ip, RX_MAC, TX_NAME);
	SYS(close, "ip link set dev %s up", TX_NAME);

	if (!setup_l2_encap_dev(encap_type, ENCAP_DEV, TX_NAME, net, tx_ip, rx_ip))
		goto close;
	SYS(close, "ip link set dev %s up", ENCAP_DEV);

	upper_ifindex = if_nametoindex(ENCAP_DEV);
	if (!ASSERT_GE(upper_ifindex, 0, "if_nametoindex upper"))
		goto close;

	if (l2_encap_uses_routing(encap_type))
		ret = send_routed_packet(af, rx_ip);
	else
		ret = send_test_packet(upper_ifindex);
	if (!ASSERT_OK(ret, "send packet"))
		goto close;

	if (!ASSERT_TRUE(*test_pass, "test_pass"))
		dump_err_stream(tc_prog);

close:
	close_netns(nstoken);
	netns_free(rx_ns);
	netns_free(tx_ns);
}

__printf(1, 2) static bool start_subtest(const char *fmt, ...)
{
	char *subtest_name;
	va_list ap;
	int r;

	va_start(ap, fmt);
	r = vasprintf(&subtest_name, fmt, ap);
	va_end(ap);
	if (!ASSERT_GE(r, 0, "format string"))
		return false;

	r = test__start_subtest(subtest_name);
	free(subtest_name);
	return r;
}

void test_xdp_context_l2_decap(void)
{
	const struct test {
		enum l2_encap_type encap_type;
		const char *encap_name;
	} tests[] = {
		{ GRE4_ENCAP, "gre4" },
		{ GRE6_ENCAP, "gre6" },
		{ VXLAN_ENCAP, "vxlan" },
		{ GENEVE_ENCAP, "geneve" },
		{ L2TPV3_ENCAP, "l2tpv3" },
		{ VLAN_ENCAP, "vlan" },
		{ QINQ_ENCAP, "qinq" },
		{ MPLS_ENCAP, "mpls" },
	};
	struct test_xdp_meta *skel;
	const struct test *t;

	skel = test_xdp_meta__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open and load skeleton"))
		return;

	for (t = tests; t < tests + ARRAY_SIZE(tests); t++) {
		if (start_subtest("%s_direct_access", t->encap_name))
			test_l2_decap(t->encap_type, skel->progs.ing_xdp,
				      skel->progs.ing_cls,
				      &skel->bss->test_pass);
		if (start_subtest("%s_dynptr_read", t->encap_name))
			test_l2_decap(t->encap_type, skel->progs.ing_xdp,
				      skel->progs.ing_cls_dynptr_read,
				      &skel->bss->test_pass);
		if (start_subtest("%s_helper_adjust_room", t->encap_name))
			test_l2_decap(t->encap_type, skel->progs.ing_xdp,
				      skel->progs.helper_skb_adjust_room,
				      &skel->bss->test_pass);
	}

	test_xdp_meta__destroy(skel);
}
