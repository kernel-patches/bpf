// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2020 Intel Corporation. */

/*
 * Some functions in this program are taken from
 * Linux kernel samples/bpf/xdpsock* and modified
 * for use.
 *
 * See drivers/net/xsk.py for detailed information on test topology
 * and prerequisite network setup.
 *
 * Each instance of this test program runs one endpoint, Tx or Rx, with a
 * single socket and a unique UMEM. Two instances validate in-order packet
 * delivery and packet content by sending packets to each other.
 *
 * Tests Information:
 * ------------------
 * These selftests test AF_XDP SKB and Native/DRV modes using veth
 * Virtual Ethernet interfaces.
 *
 * For each mode, the following tests are run:
 *    a. nopoll - soft-irq processing in run-to-completion mode
 *    b. poll - using poll() syscall
 *    c. Socket Teardown
 *       Create a Tx and a Rx socket, Tx from one socket, Rx on another. Destroy
 *       both sockets, then repeat multiple times. Only nopoll mode is used
 *    d. Bi-directional sockets
 *       Configure sockets as bi-directional tx/rx sockets, sets up fill and
 *       completion rings on each socket, tx/rx in both directions. Only nopoll
 *       mode is used
 *    e. Statistics
 *       Trigger some error conditions and ensure that the appropriate statistics
 *       are incremented. Within this test, the following statistics are tested:
 *       i.   rx dropped
 *            Increase the UMEM frame headroom to a value which results in
 *            insufficient space in the rx buffer for both the packet and the headroom.
 *       ii.  tx invalid
 *            Set the 'len' field of tx descriptors to an invalid value (umem frame
 *            size + 1).
 *       iii. rx ring full
 *            Reduce the size of the RX ring to a fraction of the fill ring size.
 *       iv.  fill queue empty
 *            Do not populate the fill queue and then try to receive pkts.
 *    f. bpf_link resource persistence
 *       Configure sockets at indexes 0 and 1, run a traffic on queue ids 0,
 *       then remove xsk sockets from queue 0 on both veth interfaces and
 *       finally run a traffic on queues ids 1
 *    g. unaligned mode
 *    h. tests for invalid and corner case Tx descriptors so that the correct ones
 *       are discarded and let through, respectively.
 *    i. 2K frame size tests
 *    j. If multi-buffer is supported, send 9k packets divided into 3 frames
 *    k. If multi-buffer and huge pages are supported, send 9k packets in a single frame
 *       using unaligned mode
 *    l. If multi-buffer is supported, try various nasty combinations of descriptors to
 *       check if they pass the validation or not
 *
 * Flow:
 * -----
 * - drivers/net/xsk.py starts two processes: Tx and Rx
 * - Each of these two processes attach to a veth interface
 * - Each process creates one AF_XDP socket connected to a unique umem for each
 *   veth interface
 * - One process listens on a TCP control port (--listen), the other one
 *   connects to it and the two synchronize each test step over that
 *   connection
 * - Tx process transmits a number of UDP packets over IPv4 or IPv6 from
 *   veth<xxxx> to veth<yyyy>, and the XDP program of Rx passes other traffic
 *   to the stack
 * - Rx process verifies if all packets were received and delivered in-order,
 *   and have the right content
 */

#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/mman.h>
#include <linux/netdev.h>
#include <linux/ethtool.h>
#include <linux/align.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <stddef.h>
#include <sys/mman.h>
#include <sys/types.h>

#include "test_xsk.h"
#include "xsk_peer.h"
#include "xsk_xdp_progs.skel.h"
#include "xsk.h"
#include "xskxceiver.h"
#include <bpf/bpf.h>
#include <linux/filter.h>
#include "kselftest.h"
#include "xsk_xdp_common.h"

enum xsk_endpoint_role {
	XSK_ENDPOINT_NONE,
	XSK_ENDPOINT_RX,
	XSK_ENDPOINT_TX,
};

static enum test_mode opt_mode = TEST_MODE_ALL;
static u32 opt_run_test = RUN_ALL_TESTS;
static enum xsk_endpoint_role opt_endpoint_role = XSK_ENDPOINT_NONE;
static bool opt_listen;
static const char *opt_peer_host;
static const char *opt_peer_port;
static const char *opt_ifname;
static const char *opt_src_ip;
static const char *opt_dst_ip;
static const struct ether_addr *opt_dst_mac;
static struct ether_addr dst_mac;
static u16 opt_udp_port;

enum {
	OPT_LISTEN = 256,
	OPT_SRC_IP,
	OPT_DST_IP,
	OPT_DST_MAC,
	OPT_UDP_PORT,
};

static void __exit_with_error(int error, const char *file, const char *func, int line)
{
	ksft_test_result_fail("[%s:%s:%i]: ERROR: %d/\"%s\"\n", file, func, line,
			      error, strerror(error));
	ksft_exit_xfail();
}

#define exit_with_error(error) __exit_with_error(error, __FILE__, __func__, __LINE__)

static bool ifobj_zc_avail(struct ifobject *ifobject)
{
	size_t umem_sz = DEFAULT_UMEM_BUFFERS * XSK_UMEM__DEFAULT_FRAME_SIZE;
	int mmap_flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE;
	struct xsk_socket_info *xsk;
	struct xsk_umem_info *umem;
	bool zc_avail = false;
	void *bufs;
	int ret;

	bufs = mmap(NULL, umem_sz, PROT_READ | PROT_WRITE, mmap_flags, -1, 0);
	if (bufs == MAP_FAILED)
		exit_with_error(errno);

	umem = calloc(1, sizeof(struct xsk_umem_info));
	if (!umem) {
		munmap(bufs, umem_sz);
		exit_with_error(ENOMEM);
	}
	umem->frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE;
	ret = xsk_configure_umem(ifobject, umem, bufs, umem_sz);
	if (ret)
		exit_with_error(-ret);

	xsk = calloc(1, sizeof(struct xsk_socket_info));
	if (!xsk)
		goto out;
	ifobject->bind_flags = XDP_USE_NEED_WAKEUP | XDP_ZEROCOPY;
	ifobject->rx_on = true;
	xsk->rxqsize = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	ret = xsk_configure_socket(xsk, umem, ifobject, false);
	if (!ret)
		zc_avail = true;

	xsk_socket__delete(xsk->xsk);
	free(xsk);
out:
	munmap(umem->buffer, umem_sz);
	xsk_umem__delete(umem->umem);
	free(umem);
	return zc_avail;
}

static struct option long_options[] = {
	{"interface", required_argument, 0, 'i'},
	{"busy-poll", no_argument, 0, 'b'},
	{"verbose", no_argument, 0, 'v'},
	{"mode", required_argument, 0, 'm'},
	{"list", no_argument, 0, 'l'},
	{"test", required_argument, 0, 't'},
	{"endpoint", required_argument, 0, 'e'},
	{"peer", required_argument, 0, 'p'},
	{"peer-port", required_argument, 0, 'P'},
	{"listen", no_argument, 0, OPT_LISTEN},
	{"src-ip", required_argument, 0, OPT_SRC_IP},
	{"dst-ip", required_argument, 0, OPT_DST_IP},
	{"dst-mac", required_argument, 0, OPT_DST_MAC},
	{"udp-port", required_argument, 0, OPT_UDP_PORT},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0}
};

static void print_usage(char **argv)
{
	const char *str =
		"  Usage: %s -i IFACE -e rx|tx -m MODE -t TEST -p HOST -P PORT\n"
		"                    --src-ip IP --dst-ip IP --dst-mac MAC --udp-port PORT [OPTIONS]\n"
		"  Options:\n"
		"  -i, --interface      Use interface\n"
		"  -v, --verbose        Verbose output\n"
		"  -b, --busy-poll      Enable busy poll\n"
		"  -m, --mode           Mode to run: skb, drv or zc\n"
		"  -l, --list           List all available tests\n"
		"  -t, --test           Test case to run, a number from -l\n"
		"  -e, --endpoint       Role of this endpoint: rx or tx\n"
		"  -p, --peer           Control host: IPv4/IPv6 address or hostname\n"
		"  -P, --peer-port      Control TCP port\n"
		"      --listen         Listen on the control port instead of connecting\n"
		"      --src-ip IP      IPv4 or IPv6 source address of the test packets\n"
		"      --dst-ip IP      Destination address, of the same family\n"
		"      --dst-mac MAC    Destination MAC address of the test packets\n"
		"      --udp-port PORT  UDP destination port, and source port of socket 0\n"
		"  -h, --help           Display this help and exit\n";

	ksft_print_msg(str, basename(argv[0]));
	ksft_exit_xfail();
}

static void bind_iface(struct ifobject *ifobj, const char *ifname, char **argv)
{
	size_t len = strlen(ifname);

	if (!len || len >= sizeof(ifobj->ifname))
		print_usage(argv);

	memcpy(ifobj->ifname, ifname, len + 1);
	ifobj->ifindex = if_nametoindex(ifobj->ifname);
	if (!ifobj->ifindex) {
		ksft_print_msg("Error: cannot resolve interface %s\n", ifobj->ifname);
		ksft_exit_fail();
	}

	if (init_iface(ifobj)) {
		ksft_print_msg("Error: cannot initialize interface %s\n", ifobj->ifname);
		ksft_exit_fail();
	}
}

static void print_tests(void)
{
	u32 i;

	printf("Tests:\n");
	for (i = 0; i < ARRAY_SIZE(tests); i++)
		printf("%u: %s\n", i, tests[i].name);
}

static void parse_command_line(struct ifobject *ifobj_tx, struct ifobject *ifobj_rx, int argc,
			       char **argv)
{
	int option_index, c;

	opterr = 0;

	for (;;) {
		c = getopt_long(argc, argv, "i:vbm:lt:e:p:P:", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'i':
			opt_ifname = optarg;
			break;
		case 'v':
			opt_verbose = true;
			break;
		case 'b':
			ifobj_tx->busy_poll = true;
			ifobj_rx->busy_poll = true;
			break;
		case 'm':
			if (!strncmp("skb", optarg, strlen(optarg)))
				opt_mode = TEST_MODE_SKB;
			else if (!strncmp("drv", optarg, strlen(optarg)))
				opt_mode = TEST_MODE_DRV;
			else if (!strncmp("zc", optarg, strlen(optarg)))
				opt_mode = TEST_MODE_ZC;
			else
				print_usage(argv);
			break;
		case 'l':
			print_tests();
			ksft_exit_pass();
			break;
		case 't':
			errno = 0;
			opt_run_test = strtol(optarg, NULL, 0);
			if (errno)
				print_usage(argv);
			break;
		case 'e':
			if (!strcmp(optarg, "rx"))
				opt_endpoint_role = XSK_ENDPOINT_RX;
			else if (!strcmp(optarg, "tx"))
				opt_endpoint_role = XSK_ENDPOINT_TX;
			else
				print_usage(argv);
			break;
		case 'p':
			opt_peer_host = optarg;
			break;
		case 'P':
			opt_peer_port = optarg;
			break;
		case OPT_LISTEN:
			opt_listen = true;
			break;
		case OPT_SRC_IP:
			opt_src_ip = optarg;
			break;
		case OPT_DST_IP:
			opt_dst_ip = optarg;
			break;
		case OPT_DST_MAC:
			opt_dst_mac = ether_aton_r(optarg, &dst_mac);
			if (!opt_dst_mac)
				print_usage(argv);
			break;
		case OPT_UDP_PORT:
			opt_udp_port = strtoul(optarg, NULL, 10);
			break;
		case 'h':
		default:
			print_usage(argv);
		}
	}

	if (!opt_ifname || opt_endpoint_role == XSK_ENDPOINT_NONE || !opt_peer_host ||
	    !*opt_peer_host || !opt_peer_port || opt_run_test == RUN_ALL_TESTS ||
	    opt_mode == TEST_MODE_ALL || !opt_src_ip || !opt_dst_ip || !opt_dst_mac ||
	    !opt_udp_port)
		print_usage(argv);
}

static void xsk_unload_xdp_programs(struct ifobject *ifobj)
{
	xsk_xdp_progs__destroy(ifobj->xdp_progs);
}

static int run_pkt_test(struct test_spec *test)
{
	int ret;

	ret = test->test_func(test);

	switch (ret) {
	case TEST_PASS:
		ksft_test_result_pass("PASS: %s %s%s\n", mode_string(test), busy_poll_string(test),
				      test->name);
		break;
	case TEST_SKIP:
		ksft_test_result_skip("SKIP: %s %s%s\n", mode_string(test), busy_poll_string(test),
				      test->name);
		break;
	case TEST_FAILURE:
		ksft_test_result_fail("FAIL: %s %s%s\n", mode_string(test), busy_poll_string(test),
				      test->name);
		break;
	default:
		ksft_test_result_fail("FAIL: %s %s%s -- Unexpected returned value (%d)\n",
				      mode_string(test), busy_poll_string(test), test->name, ret);
	}

	pkt_stream_restore_default(test);
	return ret;
}

static bool is_xdp_supported(int ifindex)
{
	int flags = XDP_FLAGS_DRV_MODE;

	LIBBPF_OPTS(bpf_link_create_opts, opts, .flags = flags);
	struct bpf_insn insns[2] = {
		BPF_MOV64_IMM(BPF_REG_0, XDP_PASS),
		BPF_EXIT_INSN()
	};
	int prog_fd, insn_cnt = ARRAY_SIZE(insns);
	int err;

	prog_fd = bpf_prog_load(BPF_PROG_TYPE_XDP, NULL, "GPL", insns, insn_cnt, NULL);
	if (prog_fd < 0)
		return false;

	err = bpf_xdp_attach(ifindex, prog_fd, flags, NULL);
	if (err) {
		close(prog_fd);
		return false;
	}

	bpf_xdp_detach(ifindex, flags, NULL);
	close(prog_fd);

	return true;
}

static u32 detect_mode_caps(struct ifobject *ifobj)
{
	if (is_xdp_supported(ifobj->ifindex)) {
		ifobj_set_cap(ifobj, XSK_CAP_DRV);
		if (ifobj_zc_avail(ifobj))
			ifobj_set_cap(ifobj, XSK_CAP_ZC);
	}

	return ifobj->caps.flags;
}

static bool mode_supported(enum test_mode mode, u32 caps)
{
	if (mode == TEST_MODE_SKB)
		return true;
	if (mode == TEST_MODE_DRV)
		return caps & XSK_CAP_DRV;
	return caps & XSK_CAP_ZC;
}

static void cleanup_iface(struct ifobject *ifobj)
{
	/* A peer shadow has a skeleton but no bound interface. */
	if (!ifobj_is_local(ifobj))
		goto unload;

	if (ifobj->xdp_prog)
		xsk_detach_xdp_program(ifobj->ifindex,
				       mode_to_xdp_flags(ifobj->mode));
unload:
	xsk_unload_xdp_programs(ifobj);
}

/* Connect the two endpoints without negotiating the remote NIC's capabilities. */
static int setup_peer(struct ifobject *local, struct ifobject *shadow,
		      struct xsk_peer **peer)
{
	/* Once BIDIRECTIONAL swaps the directions, the local side attaches the
	 * shadow's programs, so the shadow needs a skeleton of its own.
	 */
	if (xsk_load_xdp_programs(shadow))
		return TEST_FAILURE;

	*peer = xsk_peer_open(opt_peer_host, opt_peer_port, opt_listen);
	if (!*peer) {
		ksft_print_msg("Failed to connect XSK peer: %s\n", strerror(errno));
		return TEST_FAILURE;
	}

	shadow->caps = local->caps;
	memcpy(shadow->caps.mac, opt_dst_mac->ether_addr_octet, ETH_ALEN);

	xsk_set_endpoint(*peer);
	return TEST_PASS;
}

int main(int argc, char **argv)
{
	u32 cache_line_size, max_frags, umem_tailroom;
	const size_t total_tests = ARRAY_SIZE(tests);
	struct ifobject *ifobj_tx, *ifobj_rx;
	struct ifobject *shadow_ifobj;
	struct ifobject *local_ifobj;
	struct xsk_peer *peer = NULL;
	struct test_spec test = {};
	int ret = TEST_FAILURE;
	u32 caps;

	/* Use libbpf 1.0 API mode */
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	ifobj_tx = ifobject_create();
	if (!ifobj_tx)
		exit_with_error(ENOMEM);
	ifobj_rx = ifobject_create();
	if (!ifobj_rx)
		exit_with_error(ENOMEM);

	setlocale(LC_ALL, "");

	parse_command_line(ifobj_tx, ifobj_rx, argc, argv);
	/* Line-buffer stdout so verdicts reach a capturing launcher live. */
	ksft_print_header();

	cache_line_size = read_procfs_val(SMP_CACHE_BYTES_PATH);
	if (!cache_line_size) {
		ksft_print_msg("Can't get SMP_CACHE_BYTES from system, using default (64)\n");
		cache_line_size = 64;
	}

	max_frags = read_procfs_val(MAX_SKB_FRAGS_PATH);
	if (!max_frags) {
		ksft_print_msg("Can't get MAX_SKB_FRAGS from system, using default (17)\n");
		max_frags = 17;
	}
	ifobj_tx->caps.max_skb_frags = max_frags;
	ifobj_rx->caps.max_skb_frags = max_frags;

	/* 48 bytes is a part of skb_shared_info w/o frags array;
	 * 16 bytes is sizeof(skb_frag_t)
	 */
	umem_tailroom = ALIGN(48 + (max_frags * 16), cache_line_size);
	ifobj_tx->caps.umem_tailroom = umem_tailroom;
	ifobj_rx->caps.umem_tailroom = umem_tailroom;

	if (opt_run_test != RUN_ALL_TESTS && opt_run_test >= total_tests) {
		ksft_print_msg("Error: test %u does not exist.\n", opt_run_test);
		ksft_exit_xfail();
	}

	/* Before the default packet streams, which have its minimum size. */
	if (xsk_set_flow(opt_src_ip, opt_dst_ip, opt_udp_port))
		print_usage(argv);

	/* swap_directions() swaps the workers, so the shadow needs one too. */
	ifobj_tx->func_ptr = worker_testapp_validate_tx;
	ifobj_rx->func_ptr = worker_testapp_validate_rx;
	if (opt_endpoint_role == XSK_ENDPOINT_TX) {
		local_ifobj = ifobj_tx;
		shadow_ifobj = ifobj_rx;
	} else {
		local_ifobj = ifobj_rx;
		shadow_ifobj = ifobj_tx;
	}
	bind_iface(local_ifobj, opt_ifname, argv);
	caps = detect_mode_caps(local_ifobj);

	test.tx_pkt_stream_default = pkt_stream_generate(DEFAULT_PKT_CNT, MIN_PKT_SIZE);
	test.rx_pkt_stream_default = pkt_stream_generate(DEFAULT_PKT_CNT, MIN_PKT_SIZE);
	if (!test.tx_pkt_stream_default || !test.rx_pkt_stream_default)
		goto out;

	if (setup_peer(local_ifobj, shadow_ifobj, &peer))
		goto out;

	if (!mode_supported(opt_mode, caps)) {
		if (opt_mode == TEST_MODE_DRV)
			ksft_print_msg("XDP_DRV mode not supported.\n");
		else
			ksft_print_msg("zero-copy mode not supported.\n");
		ret = TEST_SKIP;
		goto out;
	}

	ksft_set_plan(1);
	test_init(&test, ifobj_tx, ifobj_rx, opt_mode, &tests[opt_run_test]);
	ret = run_pkt_test(&test);

out:
	xsk_set_endpoint(NULL);
	cleanup_iface(ifobj_tx);
	cleanup_iface(ifobj_rx);
	xsk_peer_close(peer);
	pkt_stream_delete(test.tx_pkt_stream_default);
	pkt_stream_delete(test.rx_pkt_stream_default);
	ifobject_delete(ifobj_tx);
	ifobject_delete(ifobj_rx);

	if (ret == TEST_SKIP && ksft_test_num()) {
		ksft_print_cnts();
		return KSFT_SKIP;
	}
	if (ret == TEST_SKIP)
		ksft_exit_skip("mode not supported\n");
	if (ret)
		ksft_exit_fail();
	else
		ksft_exit_pass();
}
