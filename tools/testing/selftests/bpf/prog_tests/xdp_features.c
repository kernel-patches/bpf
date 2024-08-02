// SPDX-License-Identifier: GPL-2.0

/**
 * Test XDP features
 *
 * Sets up a veth pair, and for each xdp feature under test:
 * - asks the tested interface its xdp capabilities through bpf_xdp_query
 * - attach and run some specific programs on both interfaces to check if
 *   announced capability is respected
 */
#include <pthread.h>
#include <linux/if_link.h>
#include <linux/netdev.h>
#include <linux/if_link.h>
#include <sys/socket.h>
#include "test_progs.h"
#include "network_helpers.h"
#include "xdp_features.skel.h"
#include "xdp_features.h"

#define TESTER_VETH	"v0"
#define TESTER_MAC	"00:11:22:33:44:55"
#define TESTER_VETH_IPV6	"2001:db8::1"
#define DUT_NS	"xdp_features_ns"
#define DUT_VETH	"v1"
#define DUT_MAC	"aa:bb:cc:dd:ee:ff"
#define DUT_VETH_IPV6	"2001:db8::11"
#define IP6_MASK	64
#define LOOP_DELAY_US	10000
#define TEST_NAME_MAX_LEN	32
#define TEST_PACKET_COUNT	10

struct test_data {
	struct xdp_features *skel;
	pthread_t dut_echo_thread;
	int echo_server_sock;
	int tester_ifindex;
	int dut_ifindex;
	struct sockaddr_storage tester_addr;
	struct sockaddr_storage dut_addr;
	bool quit_dut_echo_thread;
};

static void *run_dut_echo_thread(void *arg)
{
	struct test_data *t = (struct test_data *)arg;
	__u32 magic;

	while (!t->quit_dut_echo_thread) {
		struct sockaddr_storage addr;
		socklen_t addrlen;
		size_t n;

		n = recvfrom(t->echo_server_sock, &magic, sizeof(magic),
			     MSG_WAITALL, (struct sockaddr *)&addr, &addrlen);
		if (n != sizeof(magic)) {
			usleep(LOOP_DELAY_US);
			continue;
		}

		if (htonl(magic) != CMD_ECHO)
			continue;

		/* Answer echo command with the very same message */
		sendto(t->echo_server_sock, &magic, sizeof(magic),
		       MSG_NOSIGNAL | MSG_CONFIRM, (struct sockaddr *)&addr,
		       addrlen);
	}
	pthread_exit(NULL);
}

static int dut_start_echo_server(struct test_data *t)
{
	struct nstoken *token;
	int err = 0, flags;

	token = open_netns(DUT_NS);
	if (!ASSERT_OK_PTR(token, "open dut ns"))
		return -EINVAL;

	t->echo_server_sock =
		start_server(AF_INET6, SOCK_DGRAM, NULL, DUT_ECHO_PORT, 0);
	if (!ASSERT_OK_FD(t->echo_server_sock, "start dut echo server")) {
		err = t->echo_server_sock;
		goto restore_ns;
	}

	flags = fcntl(t->echo_server_sock, F_GETFL, 0);
	err = fcntl(t->echo_server_sock, F_SETFL, flags | O_NONBLOCK);
	if (!ASSERT_OK(err, "set non-blocking socket"))
		goto close_server;

	err = pthread_create(&t->dut_echo_thread, NULL, run_dut_echo_thread, t);
	if (!ASSERT_OK(err, "start dut echo thread"))
		goto close_server;

	close_netns(token);
	return 0;

close_server:
	close(t->echo_server_sock);
restore_ns:
	close_netns(token);
	return err;
}

static void dut_stop_echo_server(struct test_data *t)
{
	struct nstoken *token;

	token = open_netns(DUT_NS);
	if (!ASSERT_OK_PTR(token, "open dut ns"))
		return;

	t->quit_dut_echo_thread = true;
	pthread_join(t->dut_echo_thread, NULL);

	close(t->echo_server_sock);
	close_netns(token);
}

static int dut_attach_xdp_prog(struct test_data *t, int flags,
			       enum netdev_xdp_act drv_feature,
			       enum xdp_action action)
{
	struct bpf_program *prog;
	unsigned int key = 0;
	int err, fd = 0;

	if (drv_feature == NETDEV_XDP_ACT_NDO_XMIT) {
		struct bpf_devmap_val entry = { .ifindex = t->dut_ifindex };

		err = bpf_map__update_elem(t->skel->maps.dev_map, &key,
					   sizeof(key), &entry, sizeof(entry),
					   0);
		if (!ASSERT_OK(err, "update dev map"))
			return err;

		fd = bpf_program__fd(t->skel->progs.xdp_do_redirect_cpumap);
		action = XDP_REDIRECT;
	}

	switch (action) {
	case XDP_TX:
		prog = t->skel->progs.xdp_do_tx;
		break;
	case XDP_DROP:
		prog = t->skel->progs.xdp_do_drop;
		break;
	case XDP_ABORTED:
		prog = t->skel->progs.xdp_do_aborted;
		break;
	case XDP_PASS:
		prog = t->skel->progs.xdp_do_pass;
		break;
	case XDP_REDIRECT: {
		struct bpf_cpumap_val entry = {
			.qsize = 4096,
			.bpf_prog.fd = fd,
		};

		err = bpf_map__update_elem(t->skel->maps.cpu_map, &key,
					   sizeof(key), &entry, sizeof(entry),
					   0);
		if (!ASSERT_OK(err, "update cpu map"))
			return err;

		prog = t->skel->progs.xdp_do_redirect;
		break;
	}
	default:
		return -ENOTSUP;
	}

	err = bpf_xdp_attach(t->dut_ifindex, bpf_program__fd(prog), flags,
			     NULL);
	ASSERT_OK(err, "attach xdp prog to dut");
	return err;
}

static int dut_start_test(struct test_data *t, enum netdev_xdp_act drv_feature,
			  enum xdp_action action)
{
	int flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;
	struct nstoken *token = open_netns(DUT_NS);
	int err;

	if (!ASSERT_OK_PTR(token, "open dut ns"))
		return -EINVAL;

	err = dut_attach_xdp_prog(t, flags, drv_feature, action);
	ASSERT_OK(err, "attach xdp program to dut");
	close_netns(token);

	return err;
}

static void dut_stop_test(struct test_data *t)
{
	int flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;
	struct nstoken *token = open_netns(DUT_NS);

	if (!ASSERT_OK_PTR(token, "open dut ns"))
		return;

	bpf_xdp_detach(t->dut_ifindex, flags, NULL);
	close_netns(token);
}

static int dut_get_xdp_features(struct test_data *t, __u64 *xdp_features)
{
	struct nstoken *token = open_netns(DUT_NS);
	int err;

	if (!ASSERT_OK_PTR(token, "open dut ns"))
		return -EINVAL;

	LIBBPF_OPTS(bpf_xdp_query_opts, opts);
	err = bpf_xdp_query(t->dut_ifindex, XDP_FLAGS_DRV_MODE, &opts);
	close_netns(token);

	if (ASSERT_OK(err, "get dut interface xdp features"))
		*xdp_features = opts.feature_flags;

	return err;
}

static int send_echo_msg(struct test_data *t)
{
	__u32 magic = htonl(CMD_ECHO);
	int sockfd, n;

	sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (!ASSERT_OK_FD(sockfd, "open tester socket"))
		return sockfd;

	n = sendto(sockfd, &magic, sizeof(magic), MSG_NOSIGNAL | MSG_CONFIRM,
		   (struct sockaddr *)&t->dut_addr,
		   sizeof(struct sockaddr_storage));
	close(sockfd);

	return n == sizeof(magic) ? 0 : -EINVAL;
}

static bool tester_collect_detected_cap(struct test_data *t,
					enum netdev_xdp_act drv_feature,
					enum xdp_action action)
{
	if (!t->skel->bss->dut_stats)
		return false;

	if (drv_feature == NETDEV_XDP_ACT_NDO_XMIT)
		return t->skel->bss->tester_stats > 0;

	switch (action) {
	case XDP_PASS:
	case XDP_TX:
	case XDP_REDIRECT:
		return t->skel->bss->tester_stats > 0;
	case XDP_DROP:
	case XDP_ABORTED:
		return t->skel->bss->tester_stats == 0;
	default:
		break;
	}

	return false;
}

static void reset_test_stats(struct test_data *t,
			     struct sockaddr_storage *tester_addr,
			     struct sockaddr_storage *dut_addr)
{
	t->skel->bss->tester_stats = 0;
	t->skel->bss->dut_stats = 0;
}

static int setup_network(struct test_data *t)
{
	struct nstoken *token;
	int err;

	err = make_sockaddr(AF_INET6, DUT_VETH_IPV6, DUT_ECHO_PORT,
			    &t->dut_addr, NULL);
	if (!ASSERT_OK(err, "dut data addr"))
		return -1;

	err = make_sockaddr(AF_INET6, TESTER_VETH_IPV6, 0, &t->tester_addr,
			    NULL);
	if (!ASSERT_OK(err, "tester addr"))
		return -1;

	/* Create interfaces and testing namespace */
	SYS(fail, "ip netns add %s", DUT_NS);
	SYS(cleanup_ns,
	    "ip link add %s address %s type veth peer name %s netns %s address %s",
	    TESTER_VETH, TESTER_MAC, DUT_VETH, DUT_NS, DUT_MAC);

	/* Configure tester side in local namespace */
	SYS(cleanup_interfaces, "ip a add %s/%d nodad dev %s", TESTER_VETH_IPV6,
	    IP6_MASK, TESTER_VETH);
	SYS(cleanup_interfaces, "ip link set %s up", TESTER_VETH);
	SYS(cleanup_interfaces,
	    "ethtool -K %s tx-checksumming off > /dev/null 2>&1", TESTER_VETH);
	SYS(cleanup_interfaces, "ip neigh add %s dev %s lladdr %s",
	    DUT_VETH_IPV6, TESTER_VETH, DUT_MAC);
	t->tester_ifindex = if_nametoindex(TESTER_VETH);
	if (!ASSERT_NEQ(t->tester_ifindex, 0,
			"get tester veth interface index"))
		goto cleanup_interfaces;

	/* Configure dut side in remote namespace */
	token = open_netns(DUT_NS);
	if (!ASSERT_OK_PTR(token, "switch to dut ns"))
		goto cleanup_interfaces;
	SYS(restore_ns, "ip link set %s up", DUT_VETH);
	SYS(restore_ns, "ip a add %s/%d nodad dev %s", DUT_VETH_IPV6, IP6_MASK,
	    DUT_VETH);
	SYS(restore_ns, "ethtool -K %s tx-checksumming off > /dev/null 2>&1",
	    DUT_VETH);
	SYS(restore_ns, "ip neigh add %s dev %s lladdr %s", TESTER_VETH_IPV6,
	    DUT_VETH, TESTER_MAC);
	t->dut_ifindex = if_nametoindex(DUT_VETH);
	if (!ASSERT_NEQ(t->dut_ifindex, 0, "get dut veth interface index"))
		goto restore_ns;
	close_netns(token);

	return 0;

restore_ns:
	close_netns(token);
cleanup_interfaces:
	SYS_NOFAIL("ip link del %s", TESTER_VETH);
cleanup_ns:
	SYS_NOFAIL("ip netns del %s", DUT_NS);
fail:
	return 1;
}

static void cleanup_network(void)
{
	SYS_NOFAIL("ip netns del %s", DUT_NS);
	SYS_NOFAIL("ip link del %s", TESTER_VETH);
}

static int tester_run(char *name, struct test_data *t,
		      enum netdev_xdp_act drv_feature, enum xdp_action action)
{
	int flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;
	unsigned long long advertised_feature;

	char test_name[TEST_NAME_MAX_LEN];
	struct bpf_program *prog;
	int i, err = -EINVAL;
	bool detected_cap;

	if (drv_feature == NETDEV_XDP_ACT_NDO_XMIT || action == XDP_TX)
		prog = t->skel->progs.xdp_tester_check_tx;
	else
		prog = t->skel->progs.xdp_tester_check_rx;

	err = bpf_xdp_attach(t->tester_ifindex, bpf_program__fd(prog), flags,
			     NULL);
	if (!ASSERT_OK(err, "attach xdp program to tester"))
		goto out;

	reset_test_stats(t, &t->tester_addr, &t->dut_addr);
	err = dut_start_test(t, drv_feature, action);
	if (!ASSERT_OK(err, "send CMD_START to DUT"))
		goto out;

	err = dut_get_xdp_features(t, &advertised_feature);
	if (!ASSERT_OK(err, "get tester XDP capabilities"))
		goto out;

	for (i = 0; i < TEST_PACKET_COUNT; i++) {
		err = send_echo_msg(t);
		if (!ASSERT_OK(err, "send echo message"))
			goto out;

		usleep(LOOP_DELAY_US);
	}

	/* stop the test */
	dut_stop_test(t);

	detected_cap = tester_collect_detected_cap(t, drv_feature, action);

	snprintf(test_name, TEST_NAME_MAX_LEN, "%s advertised capabilities",
		 name);
	ASSERT_EQ(advertised_feature & drv_feature, drv_feature, test_name);
	snprintf(test_name, TEST_NAME_MAX_LEN, "%s detected capabilities",
		 name);
	ASSERT_TRUE(detected_cap, test_name);
out:
	bpf_xdp_detach(t->tester_ifindex, flags, NULL);
	return err < 0 ? err : 0;
}

void serial_test_xdp_features(void)
{
	struct test_data t = { 0 };

	if (!ASSERT_OK(setup_network(&t), "setup network"))
		return;

	t.skel = xdp_features__open();
	if (!ASSERT_OK_PTR(t.skel, "open skel"))
		goto cleanup_network;
	t.skel->rodata->tester_addr =
		((struct sockaddr_in6 *)&t.tester_addr)->sin6_addr;
	t.skel->rodata->dut_addr =
		((struct sockaddr_in6 *)&t.dut_addr)->sin6_addr;
	if (!ASSERT_OK(xdp_features__load(t.skel), "load progs"))
		goto cleanup_progs;
	if (!ASSERT_OK(xdp_features__attach(t.skel), "attach progs"))
		goto cleanup_progs;

	if (!ASSERT_OK(dut_start_echo_server(&t), "start DUT main thread"))
		goto cleanup_progs;

	if (test__start_subtest("XDP_PASS"))
		tester_run("XDP_PASS", &t, NETDEV_XDP_ACT_BASIC, XDP_PASS);

	if (test__start_subtest("XDP_DROP"))
		tester_run("XDP_DROP", &t, NETDEV_XDP_ACT_BASIC, XDP_DROP);

	if (test__start_subtest("XDP_ABORTED"))
		tester_run("XDP_ABORTED", &t, NETDEV_XDP_ACT_BASIC,
			   XDP_ABORTED);

	if (test__start_subtest("XDP_TX"))
		tester_run("XDP_TX", &t, NETDEV_XDP_ACT_BASIC, XDP_TX);

	if (test__start_subtest("XDP_REDIRECT"))
		tester_run("XDP_REDIRECT", &t, NETDEV_XDP_ACT_REDIRECT,
			   XDP_REDIRECT);

	if (test__start_subtest("XDP_NDO_XMIT"))
		tester_run("XDP_NDO_XMIT", &t, NETDEV_XDP_ACT_NDO_XMIT, 0);

	dut_stop_echo_server(&t);

cleanup_progs:
	xdp_features__destroy(t.skel);
cleanup_network:
	cleanup_network();
}
