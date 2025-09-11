// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/*
 * End-to-end eBPF tunnel test suite
 *   The file tests BPF network tunnel implementation.
 *
 * Topology:
 * ---------
 *     namespace 1       |     namespace 2
 *                       |
 *       -----------     |     -----------
 *       | tnl dev |     |     | tnl dev |  (overlay network)
 *       -----------     |     -----------
 *       metadata-mode   |     metadata-mode
 *        with bpf       |       with bpf
 *                       |
 *       ----------      |     ----------
 *       |  veth1  | --------- |  veth2  |  (underlay network)
 *       ----------    peer    ----------
 *
 *
 */

/* TODO
 * - add back the "nominal connection" test, but only once, in a general
 * - keep server on
 *   setup
 * - single pair of NS for all tests ? 
 */
#include <bpf/libbpf.h>
#include <stdio.h>
#include <unistd.h>

#include "test_progs.h"
#include "network_helpers.h"
#include "tc_helpers.h"
#include "test_tc_tunnel.skel.h"

#define MAC_ADDR_VETH1 "00:11:22:33:44:55"
#define IP4_ADDR_VETH1 "192.168.1.1"
#define IP6_ADDR_VETH1 "fd::1"

#define IP4_ADDR_VETH2 "192.168.1.2"
#define MAC_ADDR_VETH2 "66:77:88:99:AA:BB"
#define IP6_ADDR_VETH2 "fd::2"

#define TEST_IN_FILE "/tmp/test_tc_tunnel_out.bin"
#define TEST_OUT_FILE "/tmp/test_tc_tunnel_in.bin"
#define TEST_NAME_MAX_LEN	64
#define NS_NAME_MAX_LEN		128
#define PROG_NAME_MAX_LEN	64
#define TUNNEL_ARGS_MAX_LEN	128
#define BUFFER_LEN		2000
#define DEFAULT_TEST_DATA_SIZE	100
#define GSO_TEST_DATA_SIZE	BUFFER_LEN

#define TIMEOUT_MS			1000
#define TEST_PORT			8000
#define UDP_PORT			5555
#define MPLS_UDP_PORT			6635
#define FOU_MPLS_PROTO			137
#define VXLAN_ID			1
#define VXLAN_PORT			8472
#define MPLS_TABLE_ENTRIES_COUNT	65536

static char tx_buffer[BUFFER_LEN], rx_buffer[BUFFER_LEN];

struct test_priv {
	struct test_tc_tunnel *skel;
};

struct subtest_cfg {
	char *ebpf_tun_type;
	char *iproute_tun_type;
	char *mac_tun_type;
	int ipproto;
	void (*extra_decap_mod_args_cb)(struct subtest_cfg *cfg, char *dst); 
	bool tunnel_need_veth_mac;
	int (*configure_fou_rx_port)(struct subtest_cfg *cfg);
	char *tmode;
	bool expect_kern_decap_failure;
	int (*configure_mpls_cb)(struct subtest_cfg *cfg);
	bool test_gso;
/* Filled at subtest setup time, if not explicitely set by subtest config */
	char *tunnel_client_addr;
	char *tunnel_server_addr;
/* Filled at subtest setup time */
	char name[TEST_NAME_MAX_LEN];
	char client_ns[NS_NAME_MAX_LEN];
	char server_ns[NS_NAME_MAX_LEN];
	char *client_addr;
	char *server_addr;
	int client_egress_prog_fd;
	int server_ingress_prog_fd;
	char extra_decap_mod_args[TUNNEL_ARGS_MAX_LEN];
	int server_fd;
};

static int build_subtest_name(struct subtest_cfg *cfg, char *dst, size_t size)
{
	int ret;

	ret = snprintf(dst, size, "%s_%s", cfg->ebpf_tun_type,
		       cfg->mac_tun_type);

	return ret < 0 ? ret : 0;
}

static int set_subtest_egress_prog(struct subtest_cfg *cfg, struct test_tc_tunnel *skel)
{
	char prog_name[PROG_NAME_MAX_LEN];
	struct bpf_program *prog;
	int ret;


	ret = snprintf(prog_name, PROG_NAME_MAX_LEN, "__encap_");
	if (ret < 0)
		return ret;
	ret = build_subtest_name(cfg, prog_name + ret, PROG_NAME_MAX_LEN - ret);
	if (ret < 0)
		return ret;
	prog = bpf_object__find_program_by_name(skel->obj, prog_name);
	if (!prog)
		return -1;

	cfg->client_egress_prog_fd = bpf_program__fd(prog);
	cfg->server_ingress_prog_fd = bpf_program__fd(skel->progs.decap_f);
	return 0;
}

static void set_subtest_addresses(struct subtest_cfg *cfg)
{
	if (cfg->ipproto == 6) {
		cfg->client_addr = IP6_ADDR_VETH1;
		cfg->server_addr = IP6_ADDR_VETH2;
	} else {
		cfg->client_addr = IP4_ADDR_VETH1;
		cfg->server_addr = IP4_ADDR_VETH2;
	}

	/* Some specific tunnel types need specific addressing, it then
	 * has been already set in the configuration table. Otherwise,
	 * deduce the relevant addressing from the ipproto
	 */
	if (cfg->tunnel_client_addr && cfg->tunnel_server_addr)
		return;

	if (cfg->ipproto == 6) {
		cfg->tunnel_client_addr = IP6_ADDR_VETH1;
		cfg->tunnel_server_addr = IP6_ADDR_VETH2;
	} else {
		cfg->tunnel_client_addr = IP4_ADDR_VETH1;
		cfg->tunnel_server_addr = IP4_ADDR_VETH2;
	}
}

static int setup(struct test_priv *priv, struct subtest_cfg *cfg)
{
	struct nstoken *nstoken;
	int err;
	int fd;

	/* Fill subtest parameters */
	snprintf(cfg->client_ns, NS_NAME_MAX_LEN, "ns-%s-client", cfg->name);
	snprintf(cfg->server_ns, NS_NAME_MAX_LEN, "ns-%s-server", cfg->name);
	fd = open("/dev/urandom", O_RDONLY);
	if (!ASSERT_OK_FD(fd, "open urandom"))
			goto fail;
	err = read(fd, tx_buffer, BUFFER_LEN);
	close(fd);
	if (!ASSERT_EQ(err, BUFFER_LEN, "fill TX buffer"))
		goto fail;

	set_subtest_addresses(cfg);
	if (!ASSERT_OK(set_subtest_egress_prog(cfg, priv->skel),
		       "find client egress prog"))
		goto fail;
	if (cfg->extra_decap_mod_args_cb)
		cfg->extra_decap_mod_args_cb(cfg, cfg->extra_decap_mod_args);

	/* Configure the testing network */
	if (make_netns(cfg->client_ns) || make_netns(cfg->server_ns))
		goto fail;

	SYS(fail, "ip link add veth1 mtu 1500 netns %s type veth "
	    "peer name veth2 mtu 1500 netns %s",
	    cfg->client_ns, cfg->server_ns);

	nstoken = open_netns(cfg->client_ns);
	SYS(fail, "ip link set dev veth1 address " MAC_ADDR_VETH1);
	SYS(fail, "ethtool -K veth1 tso off");
	SYS(fail, "ip link set veth1 up");
	SYS(fail, "ip -4 addr add " IP4_ADDR_VETH1 "/24 dev veth1");
	SYS(fail, "ip -6 addr add " IP6_ADDR_VETH1 "/64 dev veth1 nodad");
	SYS(fail, "ip -4 route flush table main");
	SYS(fail, "ip -6 route flush table main");
	SYS(fail, "ip -4 route add " IP4_ADDR_VETH2 " mtu 1450 dev veth1");
	SYS(fail, "ip -6 route add " IP6_ADDR_VETH2 " mtu 1430 dev veth1");
	close_netns(nstoken);


	nstoken = open_netns(cfg->server_ns);
	SYS(fail, "ip link set dev veth2 address " MAC_ADDR_VETH2);
	SYS(fail, "ip link set veth2 up");
	SYS(fail, "ip -4 addr add " IP4_ADDR_VETH2 "/24 dev veth2");
	SYS(fail, "ip -6 addr add " IP6_ADDR_VETH2 "/64 dev veth2 nodad");
	close_netns(nstoken);

	SYS_NOFAIL("dd if=/dev/urandom of=" TEST_IN_FILE
		   " bs=100 count=1 status=none");

	return 0;
fail:
	return -1;
}

static void cleanup(struct subtest_cfg *cfg)
{
	SYS_NOFAIL("ip netns exec %s killall nc", cfg->client_ns);
	SYS_NOFAIL("ip netns del %s", cfg->client_ns);
	SYS_NOFAIL("ip netns del %s", cfg->server_ns);
}

static int run_server(struct subtest_cfg *cfg)
{
	struct nstoken *nstoken = open_netns(cfg->server_ns);
	int family = cfg->ipproto == 6 ? AF_INET6 : AF_INET;

	cfg->server_fd =
		start_server(family, SOCK_STREAM, cfg->server_addr, TEST_PORT, TIMEOUT_MS);
	close_netns(nstoken);
	if (!ASSERT_OK_FD(cfg->server_fd, "start server"))
		return -1;

	return 0;
}

static int check_server_rx_data(struct subtest_cfg *cfg, int len)
{
	struct nstoken *nstoken = open_netns(cfg->server_ns);
	int err, fd;


	fd = accept(cfg->server_fd, NULL, NULL);
	if (!ASSERT_OK_FD(fd, "accept connection"))
		goto fail;
	err = recv(fd, rx_buffer, len, 0);
	if (!ASSERT_EQ(err, len, "check rx data len"))
		goto fail;
	if (!ASSERT_MEMEQ(tx_buffer, rx_buffer, len, "check received data"))
		goto fail;
	close_netns(nstoken);
	return 0;
fail:
	close_netns(nstoken);
	return 1;

}

static int send_and_test_data(struct subtest_cfg *cfg, bool must_succeed)
{
	struct nstoken *nstoken = open_netns(cfg->client_ns);
	int family = cfg->ipproto == 6 ? AF_INET6 : AF_INET;
	int err, client_fd;

	client_fd = connect_to_addr_str(family, SOCK_STREAM, cfg->server_addr, TEST_PORT,
			    NULL);
	if (!must_succeed && !ASSERT_ERR(client_fd, "connection that must fail"))
		goto fail;
	else if (!must_succeed)
		return 0;

	if (!ASSERT_OK_FD(client_fd, "connection that must succeed"))
			goto fail;

	err = send(client_fd, tx_buffer, DEFAULT_TEST_DATA_SIZE, 0);
	if (!ASSERT_EQ(err, DEFAULT_TEST_DATA_SIZE, "send data from client"))
		goto fail;
	if (!ASSERT_OK(check_server_rx_data(cfg, DEFAULT_TEST_DATA_SIZE),
		       "check received data"))
		goto fail;

	if (cfg->test_gso) {
		err = send(client_fd, tx_buffer, GSO_TEST_DATA_SIZE, 0);
		if (!ASSERT_EQ(err, GSO_TEST_DATA_SIZE,
			       "send (large) data from client"))
			goto fail;
		if (!ASSERT_OK(check_server_rx_data(cfg,
						    DEFAULT_TEST_DATA_SIZE),
			       "check received (large) data"))
			goto fail;
	}

	close(client_fd);
	close_netns(nstoken);
	return 0;
fail:
	close(client_fd);
	close_netns(nstoken);
	return -1;
}
static void vxlan_decap_mod_args_cb(struct subtest_cfg *cfg, char *dst)
{
	snprintf(dst, TUNNEL_ARGS_MAX_LEN, "id %d dstport %d udp6zerocsumrx",
		 VXLAN_ID, VXLAN_PORT);
}

static void udp_decap_mod_args_cb(struct subtest_cfg *cfg, char *dst)
{
	bool is_mpls = !strcmp(cfg->mac_tun_type, "mpls");
	snprintf(dst, TUNNEL_ARGS_MAX_LEN,
		 "encap fou encap-sport auto encap-dport %d",
		 is_mpls ? MPLS_UDP_PORT : UDP_PORT);
}

static int configure_fou_rx_port_cb(struct subtest_cfg *cfg)
{
	bool is_mpls = strcmp(cfg->mac_tun_type, "mpls") == 0;
	char *fou_proto;

	if (is_mpls)
		fou_proto = "137";
	else
		fou_proto = cfg->ipproto == 6 ? "41" : "4";

	SYS(fail, "ip fou add port %d ipproto %s%s",
	    is_mpls ? MPLS_UDP_PORT : UDP_PORT, fou_proto,
	    cfg->ipproto == 6 ? " -6" : "");

	return 0;
fail:
	return 1;
}


static int update_tunnel_intf_addr(struct subtest_cfg *cfg)
{
	SYS(fail, "ip link set dev testtun0 address " MAC_ADDR_VETH2);
	return 0;
fail:
	return -1;
}

static int configure_kernel_for_mpls(struct subtest_cfg *cfg)
{
	SYS(fail, "sysctl -qw net.mpls.platform_labels=%d",
	    MPLS_TABLE_ENTRIES_COUNT);
	SYS(fail, "ip -f mpls route add 1000 dev lo");
	SYS(fail, "ip link set lo up");
	SYS(fail, "sysctl -qw net.mpls.conf.testtun0.input=1");
	SYS(fail, "sysctl -qw net.ipv4.conf.lo.rp_filter=0");
	return 0;
fail:
	return -1;
}

static int configure_encapsulation(struct subtest_cfg *cfg)
{
	struct nstoken *nstoken = open_netns(cfg->client_ns);
	int ret;
	ret = generic_attach_egr("veth1", cfg->client_egress_prog_fd);
	close_netns(nstoken);

	return ret;
}

static int configure_kernel_decapsulation (struct subtest_cfg *cfg)
{
	struct nstoken *nstoken = open_netns(cfg->server_ns);

	if (cfg->configure_fou_rx_port && !ASSERT_OK(
		    cfg->configure_fou_rx_port(cfg), "configure FOU RX port"))
		goto fail;
	SYS(fail, "ip link add name testtun0 type %s %s remote %s local %s %s",
	    cfg->iproute_tun_type, cfg->tmode ? cfg->tmode : "",
	    cfg->tunnel_client_addr, cfg->tunnel_server_addr,
	    cfg->extra_decap_mod_args);
	if (cfg->tunnel_need_veth_mac &&
	    !ASSERT_OK(update_tunnel_intf_addr(cfg), "update testtun0 mac"))
		goto fail;
	if (cfg->configure_mpls_cb &&
	    (!ASSERT_OK(configure_kernel_for_mpls(cfg),
			"configure MPLS decap")))
		goto fail;
	SYS(fail, "sysctl -qw net.ipv4.conf.all.rp_filter=0");
	SYS(fail, "sysctl -qw net.ipv4.conf.testtun0.rp_filter=0");
	SYS(fail, "ip link set dev testtun0 up");
	close_netns(nstoken);
	return 0;
fail:
	close_netns(nstoken);
	return -1;
}

static int configure_ebpf_decapsulation(struct subtest_cfg *cfg)
{
	struct nstoken *nstoken = open_netns(cfg->server_ns);
	SYS(fail, "ip link del testtun0");
	if (!ASSERT_OK(generic_attach_igr("veth2", cfg->server_ingress_prog_fd),
		       "attach_program"))
		goto fail;
	close_netns(nstoken);
	return 0;
fail:
	close_netns(nstoken);
	return -1;

}

static void run_test(struct subtest_cfg * cfg)
{
	// Attach encapsulation program to client, communication must fail
	if (!ASSERT_OK(configure_encapsulation(cfg), "configure encapsulation"))
		return;
	run_server(cfg);
	if (!ASSERT_OK(send_and_test_data(cfg, false), "connect with encap prog only"))
		return;

	/* Insert kernel decap module, connection must succeed */
	if (!ASSERT_OK(configure_kernel_decapsulation(cfg), "configure kernel decapsulation"))
		return;
	if (!ASSERT_OK(send_and_test_data(cfg, !cfg->expect_kern_decap_failure),
		       "connect with encap prog and kern decap"))
		return;

	// Replace kernel module with BPF decap, test must pass
	if (!ASSERT_OK(configure_ebpf_decapsulation(cfg), "configure ebpf decapsulation"))
		return;

	ASSERT_OK(send_and_test_data(cfg, true), "connect with encap and decap progs");
}

struct subtest_cfg subtests_cfg[] = {
	{
		.ebpf_tun_type = "ipip",
		.mac_tun_type = "none",
		.iproute_tun_type = "ipip",
		.ipproto = 4,
	},
	{
		.ebpf_tun_type = "ipip6",
		.mac_tun_type = "none",
		.iproute_tun_type = "ip6tnl",
		.ipproto = 4,
		.tunnel_client_addr = IP6_ADDR_VETH1,
		.tunnel_server_addr = IP6_ADDR_VETH2,
	},
	{
		.ebpf_tun_type = "ip6tnl",
		.iproute_tun_type = "ip6tnl",
		.mac_tun_type = "none",
		.ipproto = 6,
	},
	{
		.mac_tun_type = "none",
		.ebpf_tun_type = "sit",
		.iproute_tun_type = "sit",
		.ipproto = 6,
		.tunnel_client_addr = IP4_ADDR_VETH1,
		.tunnel_server_addr = IP4_ADDR_VETH2,
	},
	{
		.ebpf_tun_type = "vxlan",
		.mac_tun_type = "eth",
		.iproute_tun_type = "vxlan",
		.ipproto = 4,
		.extra_decap_mod_args_cb = vxlan_decap_mod_args_cb,
		.tunnel_need_veth_mac = true
	},
	{
		.ebpf_tun_type = "ip6vxlan",
		.mac_tun_type = "eth",
		.iproute_tun_type = "vxlan",
		.ipproto = 6,
		.extra_decap_mod_args_cb = vxlan_decap_mod_args_cb,
		.tunnel_need_veth_mac = true
	},
	{
		.ebpf_tun_type = "gre",
		.mac_tun_type = "none",
		.iproute_tun_type = "gre",
		.ipproto = 4,
	},
	{
		.ebpf_tun_type = "gre",
		.mac_tun_type = "eth",
		.iproute_tun_type = "gretap",
		.ipproto = 4,
		.tunnel_need_veth_mac = true
	},
	{
		.ebpf_tun_type = "gre",
		.mac_tun_type = "mpls",
		.iproute_tun_type = "gre",
		.ipproto = 4,
		.configure_mpls_cb = configure_kernel_for_mpls
	},
	{
		.ebpf_tun_type = "ip6gre",
		.mac_tun_type = "none",
		.iproute_tun_type = "ip6gre",
		.ipproto = 6,
	},
	{
		.ebpf_tun_type = "ip6gre",
		.mac_tun_type = "eth",
		.iproute_tun_type = "ip6gretap",
		.ipproto = 6,
		.tunnel_need_veth_mac = true
	},
	{
		.ebpf_tun_type = "ip6gre",
		.mac_tun_type = "mpls",
		.iproute_tun_type = "ip6gre",
		.ipproto = 6,
		.configure_mpls_cb = configure_kernel_for_mpls
	},
	{
		.ebpf_tun_type = "udp",
		.mac_tun_type = "none",
		.iproute_tun_type = "ipip",
		.ipproto = 4,
		.extra_decap_mod_args_cb = udp_decap_mod_args_cb,
		.configure_fou_rx_port = configure_fou_rx_port_cb,
	},
	{
		.ebpf_tun_type = "udp",
		.mac_tun_type = "eth",
		.iproute_tun_type = "ipip",
		.ipproto = 4,
		.extra_decap_mod_args_cb = udp_decap_mod_args_cb,
		.configure_fou_rx_port = configure_fou_rx_port_cb,
		.expect_kern_decap_failure = true
	},
	{
		.ebpf_tun_type = "udp",
		.mac_tun_type = "mpls",
		.iproute_tun_type = "ipip",
		.ipproto = 4,
		.extra_decap_mod_args_cb = udp_decap_mod_args_cb,
		.configure_fou_rx_port = configure_fou_rx_port_cb,
		.tmode = "mode any ttl 255",
		.configure_mpls_cb = configure_kernel_for_mpls
	},
	{
		.ebpf_tun_type = "ip6udp",
		.mac_tun_type = "none",
		.iproute_tun_type = "ip6tnl",
		.ipproto = 6,
		.extra_decap_mod_args_cb = udp_decap_mod_args_cb,
		.configure_fou_rx_port = configure_fou_rx_port_cb,
	},
	{
		.ebpf_tun_type = "ip6udp",
		.mac_tun_type = "eth",
		.iproute_tun_type = "ip6tnl",
		.ipproto = 6,
		.extra_decap_mod_args_cb = udp_decap_mod_args_cb,
		.configure_fou_rx_port = configure_fou_rx_port_cb,
		.expect_kern_decap_failure = true
	},
	{
		.ebpf_tun_type = "ip6udp",
		.mac_tun_type = "mpls",
		.iproute_tun_type = "ip6tnl",
		.ipproto = 6,
		.extra_decap_mod_args_cb = udp_decap_mod_args_cb,
		.configure_fou_rx_port = configure_fou_rx_port_cb,
		.tmode = "mode any ttl 255",
		.expect_kern_decap_failure = true
	},
};

int subtests_count = sizeof(subtests_cfg)/sizeof(struct subtest_cfg);


void test_tc_tunnel(void)
{
	struct test_priv *priv = calloc(1, sizeof(struct test_priv));
	struct subtest_cfg *cfg;
	int i, ret;

	if(!ASSERT_NEQ(priv, NULL, "alloc test priv"))
		return;

	priv->skel = test_tc_tunnel__open_and_load();
	if(!ASSERT_OK_PTR(priv->skel, "skel open and load")) {
		free(priv);
		return;
	}

	for (i = 0; i < subtests_count; i++) {
		cfg = &subtests_cfg[i];
		ret = build_subtest_name(cfg, cfg->name, TEST_NAME_MAX_LEN);
		if (ret < 0 || !test__start_subtest(cfg->name))
			continue;
		setup(priv, cfg);
		run_test(cfg);
		cleanup(cfg);
	}
}
