// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/*
 * Topology:
 * ---------
 *   NS0 namespace         |   NS1 namespace        | NS2 namespace
 *                         |                        |
 *   +---------------+     |   +---------------+    |
 *   |    ipsec0     |---------|    ipsec0     |    |
 *   | 192.168.1.100 |     |   | 192.168.1.200 |    |
 *   | if_id: bpf    |     |   +---------------+    |
 *   +---------------+     |                        |
 *           |             |                        |   +---------------+
 *           |             |                        |   |    ipsec0     |
 *           \------------------------------------------| 192.168.1.200 |
 *                         |                        |   +---------------+
 *                         |                        |
 *                         |                        | (overlay network)
 *      ------------------------------------------------------
 *                         |                        | (underlay network)
 *   +--------------+      |   +--------------+     |
 *   |    veth01    |----------|    veth10    |     |
 *   | 172.16.1.100 |      |   | 172.16.1.200 |     |
 *   ---------------+      |   +--------------+     |
 *                         |                        |
 *   +--------------+      |                        |   +--------------+
 *   |    veth02    |-----------------------------------|    veth20    |
 *   | 172.16.2.100 |      |                        |   | 172.16.2.200 |
 *   +--------------+      |                        |   +--------------+
 *
 *
 * Test Packet flow
 * -----------
 *  The tests perform 'ping 192.168.1.200' from the NS0 namespace:
 *  1) request is routed to NS0 ipsec0
 *  2) NS0 ipsec0 tc egress BPF program is triggered and sets the if_id based
 *     on a map value. This makes the ipsec0 device in external mode select the
 *     destination tunnel
 *  3) ping reaches the other namespace (NS1 or NS2 based on which if_id was
 *     used) and response is sent
 *  4) response is received on NS0 ipsec0, tc ingress program is triggered and
 *     records the response if_id in the map
 *  5) requested if_id is compared with received if_id
 */

#include <net/if.h>

#include "test_progs.h"
#include "network_helpers.h"
#include "test_xfrm_info_kern.skel.h"

#define NS0 "xfrm_test_ns0"
#define NS1 "xfrm_test_ns1"
#define NS2 "xfrm_test_ns2"

#define IF_ID_0_TO_1 1
#define IF_ID_0_TO_2 2
#define IF_ID_1 3
#define IF_ID_2 4

#define IP4_ADDR_VETH01 "172.16.1.100"
#define IP4_ADDR_VETH10 "172.16.1.200"
#define IP4_ADDR_VETH02 "172.16.2.100"
#define IP4_ADDR_VETH20 "172.16.2.200"

#define ESP_DUMMY_PARAMS \
    "proto esp aead 'rfc4106(gcm(aes))' " \
    "0xe4d8f4b4da1df18a3510b3781496daa82488b713 128 mode tunnel "

#define PING_ARGS "-i 0.01 -c 3 -w 10 -q"

#define SYS(fmt, ...)						\
	({							\
		char cmd[1024];					\
		snprintf(cmd, sizeof(cmd), fmt, ##__VA_ARGS__);	\
		if (!ASSERT_OK(system(cmd), cmd))		\
			goto fail;				\
	})

#define SYS_NOFAIL(fmt, ...)					\
	({							\
		char cmd[1024];					\
		snprintf(cmd, sizeof(cmd), fmt, ##__VA_ARGS__);	\
		system(cmd);					\
	})

static int attach_tc_prog(struct bpf_tc_hook *hook, int igr_fd, int egr_fd)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts1, .handle = 1,
			    .priority = 1, .prog_fd = igr_fd);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts2, .handle = 1,
			    .priority = 1, .prog_fd = egr_fd);
	int ret;

	ret = bpf_tc_hook_create(hook);
	if (!ASSERT_OK(ret, "create tc hook"))
		return ret;

	if (igr_fd >= 0) {
		hook->attach_point = BPF_TC_INGRESS;
		ret = bpf_tc_attach(hook, &opts1);
		if (!ASSERT_OK(ret, "bpf_tc_attach")) {
			bpf_tc_hook_destroy(hook);
			return ret;
		}
	}

	if (egr_fd >= 0) {
		hook->attach_point = BPF_TC_EGRESS;
		ret = bpf_tc_attach(hook, &opts2);
		if (!ASSERT_OK(ret, "bpf_tc_attach")) {
			bpf_tc_hook_destroy(hook);
			return ret;
		}
	}

	return 0;
}

static void cleanup(void)
{
	SYS_NOFAIL("test -f /var/run/netns/" NS0 " && ip netns delete " NS0);
	SYS_NOFAIL("test -f /var/run/netns/" NS1 " && ip netns delete " NS1);
	SYS_NOFAIL("test -f /var/run/netns/" NS2 " && ip netns delete " NS2);
}

static int config_underlay(void)
{
	SYS("ip netns add " NS0);
	SYS("ip netns add " NS1);
	SYS("ip netns add " NS2);

	/* NS0 <-> NS1 [veth01 <-> veth10] */
	SYS("ip link add veth01 netns " NS0 " type veth peer name veth10 netns " NS1);
	SYS("ip -net " NS0 " addr add " IP4_ADDR_VETH01 "/24 dev veth01");
	SYS("ip -net " NS0 " link set dev veth01 up");
	SYS("ip -net " NS1 " addr add " IP4_ADDR_VETH10 "/24 dev veth10");
	SYS("ip -net " NS1 " link set dev veth10 up");

	/* NS0 <-> NS2 [veth02 <-> veth20] */
	SYS("ip link add veth02 netns " NS0 " type veth peer name veth20 netns " NS2);
	SYS("ip -net " NS0 " addr add " IP4_ADDR_VETH02 "/24 dev veth02");
	SYS("ip -net " NS0 " link set dev veth02 up");
	SYS("ip -net " NS2 " addr add " IP4_ADDR_VETH20 "/24 dev veth20");
	SYS("ip -net " NS2 " link set dev veth20 up");

	return 0;
fail:
	return -1;
}

static int setup_xfrm_tunnel_ns(const char *ns, const char *ipv4_local,
				const char *ipv4_remote, int if_id)
{
	/* State: local -> remote */
	SYS("ip -net %s xfrm state add src %s dst %s spi 1 "
	    ESP_DUMMY_PARAMS "if_id %d", ns, ipv4_local, ipv4_remote, if_id);

	/* State: local <- remote */
	SYS("ip -net %s xfrm state add src %s dst %s spi 1 "
	    ESP_DUMMY_PARAMS "if_id %d", ns, ipv4_remote, ipv4_local, if_id);

	/* Policy: local -> remote */
	SYS("ip -net %s xfrm policy add dir out src 0.0.0.0/0 dst 0.0.0.0/0 "
	    "if_id %d tmpl src %s dst %s proto esp mode tunnel if_id %d", ns,
	    if_id, ipv4_local, ipv4_remote, if_id);

	/* Policy: local <- remote */
	SYS("ip -net %s xfrm policy add dir in src 0.0.0.0/0 dst 0.0.0.0/0 "
	    "if_id %d tmpl src %s dst %s proto esp mode tunnel if_id %d", ns,
	    if_id, ipv4_remote, ipv4_local, if_id);

	return 0;
fail:
	return -1;
}

static int setup_xfrm_tunnel(const char *ns_a, const char *ns_b,
			     const char *ipv4_a, const char *ipv4_b,
			     int if_id_a, int if_id_b)
{
	return setup_xfrm_tunnel_ns(ns_a, ipv4_a, ipv4_b, if_id_a) ||
		setup_xfrm_tunnel_ns(ns_b, ipv4_b, ipv4_a, if_id_b);
}

static int config_overlay(void)
{
	if (setup_xfrm_tunnel(NS0, NS1, IP4_ADDR_VETH01, IP4_ADDR_VETH10,
			      IF_ID_0_TO_1, IF_ID_1))
		goto fail;
	if (setup_xfrm_tunnel(NS0, NS2, IP4_ADDR_VETH02, IP4_ADDR_VETH20,
			      IF_ID_0_TO_2, IF_ID_2))
		goto fail;

	SYS("ip -net " NS0 " link add ipsec0 type xfrm external");
	SYS("ip -net " NS0 " addr add 192.168.1.100/24 dev ipsec0");
	SYS("ip -net " NS0 " link set dev ipsec0 up");

	SYS("ip -net " NS1 " link add ipsec0 type xfrm external");
	SYS("ip -net " NS1 " addr add 192.168.1.200/32 dev ipsec0");
	SYS("ip -net " NS1 " link set dev ipsec0 up");
	SYS("ip -net " NS1 " route add 192.168.1.100/32 dev ipsec0 encap xfrm if_id %d", IF_ID_1);

	SYS("ip -net " NS2 " link add ipsec0 type xfrm if_id %d", IF_ID_2);
	SYS("ip -net " NS2 " addr add 192.168.1.200/24 dev ipsec0");
	SYS("ip -net " NS2 " link set dev ipsec0 up");

	return 0;
fail:
	return -1;
}

static int test_ping(int family, const char *addr)
{
	SYS("%s %s %s > /dev/null", ping_command(family), PING_ARGS, addr);
	return 0;
fail:
	return -1;
}

static int test_xfrm_ping(int dst_if_id_map_fd, u32 if_id)
{
	u32 dst_if_id;
	int key, err;

	key = 0;
	dst_if_id = if_id;
	err = bpf_map_update_elem(dst_if_id_map_fd, &key, &dst_if_id, BPF_ANY);
	if (!ASSERT_OK(err, "update bpf dst_if_id_map"))
		return -1;

	if (test_ping(AF_INET, "192.168.1.200"))
		return -1;

	key = 1;
	dst_if_id = 0;
	err = bpf_map_lookup_elem(dst_if_id_map_fd, &key, &dst_if_id);
	if (!ASSERT_OK(err, "lookup bpf dst_if_id_map"))
		return -1;

	if (!ASSERT_EQ(dst_if_id, if_id, "if_id"))
		return -1;

	return 0;
}

static void test_xfrm_info(void)
{
	int get_xfrm_info_prog_fd, set_xfrm_info_prog_fd;
	struct test_xfrm_info_kern *skel = NULL;
	struct nstoken *nstoken = NULL;
	int dst_if_id_map_fd = -1;
	int ifindex = -1;
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook,
			    .attach_point = BPF_TC_INGRESS);

	/* load and attach bpf progs to ipsec dev tc hook point */
	skel = test_xfrm_info_kern__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_xfrm_info_kern__open_and_load"))
		goto done;
	nstoken = open_netns(NS0);
	ifindex = if_nametoindex("ipsec0");
	if (!ASSERT_NEQ(ifindex, 0, "ipsec0 ifindex"))
		goto done;
	tc_hook.ifindex = ifindex;
	set_xfrm_info_prog_fd = bpf_program__fd(skel->progs.set_xfrm_info);
	get_xfrm_info_prog_fd = bpf_program__fd(skel->progs.get_xfrm_info);
	if (!ASSERT_GE(set_xfrm_info_prog_fd, 0, "bpf_program__fd"))
		goto done;
	if (!ASSERT_GE(get_xfrm_info_prog_fd, 0, "bpf_program__fd"))
		goto done;
	if (attach_tc_prog(&tc_hook, get_xfrm_info_prog_fd,
			   set_xfrm_info_prog_fd))
		goto done;
	dst_if_id_map_fd = bpf_map__fd(skel->maps.dst_if_id_map);
	if (!ASSERT_GE(dst_if_id_map_fd, 0, "bpf_map__fd"))
		goto done;

	if (!ASSERT_EQ(test_xfrm_ping(dst_if_id_map_fd, IF_ID_0_TO_1), 0,
		       "ping " NS1))
		goto done;
	if (!ASSERT_EQ(test_xfrm_ping(dst_if_id_map_fd, IF_ID_0_TO_2), 0,
		       "ping " NS2))
		goto done;

done:
	if (nstoken)
		close_netns(nstoken);
	if (dst_if_id_map_fd >= 0)
		close(dst_if_id_map_fd);
	if (skel)
		test_xfrm_info_kern__destroy(skel);
}

#define RUN_TEST(name)							\
	({								\
		if (test__start_subtest(#name)) {			\
			test_ ## name();				\
		}							\
	})

static void *test_xfrm_info_run_tests(void *arg)
{
	cleanup();

	config_underlay();
	config_overlay();

	RUN_TEST(xfrm_info);

	cleanup();

	return NULL;
}

static int probe_iproute2(void)
{
	if (SYS_NOFAIL("ip link add type xfrm help 2>&1 | "
		       "grep external > /dev/null")) {
		fprintf(stdout, "%s:SKIP: iproute2 with xfrm external support needed for this test\n", __func__);
		return -1;
	}
	return 0;
}

void serial_test_xfrm_info(void)
{
	pthread_t test_thread;
	int err;

	if (probe_iproute2()) {
		test__skip();
		return;
	}

	/* Run the tests in their own thread to isolate the namespace changes
	 * so they do not affect the environment of other tests.
	 * (specifically needed because of unshare(CLONE_NEWNS) in open_netns())
	 */
	err = pthread_create(&test_thread, NULL, &test_xfrm_info_run_tests, NULL);
	if (ASSERT_OK(err, "pthread_create"))
		ASSERT_OK(pthread_join(test_thread, NULL), "pthread_join");
}
