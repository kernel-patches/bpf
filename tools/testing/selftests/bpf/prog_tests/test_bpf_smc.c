// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <linux/genetlink.h>
#include "netlink_helpers.h"
#include "network_helpers.h"
#include "bpf_smc.skel.h"

#ifndef IPPROTO_SMC
#define IPPROTO_SMC 256
#endif

#define CLIENT_IP			"127.0.0.1"
#define SERVER_IP			"127.0.1.0"
#define SERVER_IP_VIA_RISK_PATH	"127.0.2.0"

#define SERVICE_1	80
#define SERVICE_2	443
#define SERVICE_3	8443

#define TEST_NS	"bpf_smc_netns"

static struct netns_obj *test_netns;

struct smc_policy_ip_key {
	__u32  sip;
	__u32  dip;
};

struct smc_policy_ip_value {
	__u8	mode;
};

#if defined(__s390x__)
/* s390x has default seid  */
static bool setup_ueid(void) { return true; }
static void cleanup_ueid(void) {}
#else
enum {
	SMC_NETLINK_ADD_UEID = 10,
	SMC_NETLINK_REMOVE_UEID
};

enum {
	SMC_NLA_EID_TABLE_UNSPEC,
	SMC_NLA_EID_TABLE_ENTRY,    /* string */
};

#define SMC_GENL_FAMILY_NAME	"SMC_GEN_NETLINK"
#define SMC_GENL_FAMILY_VERSION	1
#define SMC_BPFTEST_UEID	"SMC-BPFTEST-UEID"
#define SMC_BPFTEST_UEID_LEN	32

static __u16 smc_nl_family_id;

static bool get_smc_nl_family_id(void)
{
	int fd, ret;
	pid_t pid;

	pid = getpid();
	fd = genl_open(pid);
	if (!ASSERT_OK_FD(fd, "nl_family socket"))
		return false;

	ret = genl_resolve_family(fd, SMC_GENL_FAMILY_NAME);
	if (!ASSERT_GT(ret, 0, "nl_family query"))
		goto fail;

	smc_nl_family_id = ret;
	close(fd);
	return true;
fail:
	close(fd);
	return false;
}

static bool smc_ueid(int op)
{
	char test_ueid[SMC_BPFTEST_UEID_LEN + 1] = {};
	struct genl_req req = {};
	int fd, ret;
	pid_t pid;

	/* UEID required */
	memset(test_ueid, ' ', SMC_BPFTEST_UEID_LEN);
	memcpy(test_ueid, SMC_BPFTEST_UEID, sizeof(SMC_BPFTEST_UEID) - 1);
	pid = getpid();
	fd = genl_open(pid);
	if (!ASSERT_OK_FD(fd, "ueid socket"))
		return false;

	req.nlh.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	req.nlh.nlmsg_type = smc_nl_family_id;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nlh.nlmsg_pid = pid;
	req.genl.cmd = op;
	req.genl.version = SMC_GENL_FAMILY_VERSION;
	ret = addattrstrz(&req.nlh, sizeof(req), SMC_NLA_EID_TABLE_ENTRY,
			  test_ueid);
	if (!ASSERT_OK(ret, "ueid attribute"))
		goto fail;

	ret = genl_send(fd, &req.nlh);
	if (!ASSERT_OK(ret, "ueid cmd"))
		goto fail;

	ret = genl_recv(fd, req.nlh.nlmsg_seq, smc_nl_family_id, false);
	switch (op) {
	case SMC_NETLINK_REMOVE_UEID:
		if (!ASSERT_FALSE(ret && ret != -ENOENT, "ueid remove"))
			goto fail;
		break;
	case SMC_NETLINK_ADD_UEID:
		if (!ASSERT_OK(ret, "ueid add"))
			goto fail;
		break;
	default:
		break;
	}

	close(fd);
	return true;
fail:
	close(fd);
	return false;
}

static bool setup_ueid(void)
{
	/* get smc nl id */
	if (!get_smc_nl_family_id())
		return false;
	/* clear old ueid for bpftest */
	smc_ueid(SMC_NETLINK_REMOVE_UEID);
	/* smc-loopback required ueid */
	return smc_ueid(SMC_NETLINK_ADD_UEID);
}

static void cleanup_ueid(void)
{
	smc_ueid(SMC_NETLINK_REMOVE_UEID);
}
#endif /* __s390x__ */

static bool setup_netns(void)
{
	test_netns = netns_new(TEST_NS, true);
	if (!ASSERT_OK_PTR(test_netns, "open net namespace"))
		goto fail_netns;

	SYS(fail_ip, "ip addr add 127.0.1.0/8 dev lo");
	SYS(fail_ip, "ip addr add 127.0.2.0/8 dev lo");

	return true;
fail_ip:
	netns_free(test_netns);
fail_netns:
	return false;
}

static void cleanup_netns(void)
{
	netns_free(test_netns);
}

static bool setup_smc(void)
{
	if (!setup_ueid())
		return false;

	if (!setup_netns())
		goto fail_netns;

	return true;
fail_netns:
	cleanup_ueid();
	return false;
}

static int set_client_addr_cb(int fd, void *opts)
{
	const char *src = (const char *)opts;
	struct sockaddr_in localaddr;

	localaddr.sin_family = AF_INET;
	localaddr.sin_port = htons(0);
	localaddr.sin_addr.s_addr = inet_addr(src);
	return !ASSERT_OK(bind(fd, &localaddr, sizeof(localaddr)), "client bind");
}

static void run_link(const char *src, const char *dst, int port)
{
	struct network_helper_opts opts = {0};
	int server, client;

	server = start_server_str(AF_INET, SOCK_STREAM, dst, port, NULL);
	if (!ASSERT_OK_FD(server, "start service_1"))
		return;

	opts.proto = IPPROTO_TCP;
	opts.post_socket_cb = set_client_addr_cb;
	opts.cb_opts = (void *)src;

	client = connect_to_fd_opts(server, &opts);
	if (!ASSERT_OK_FD(client, "start connect"))
		goto fail_client;

	close(client);
fail_client:
	close(server);
}

static void block_link(int map_fd, const char *src, const char *dst)
{
	struct smc_policy_ip_value val = { .mode = /* block */ 0 };
	struct smc_policy_ip_key key = {
		.sip = inet_addr(src),
		.dip = inet_addr(dst),
	};

	bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);
}

/*
 * This test describes a real-life service topology as follows:
 *
 *                             +-------------> service_1
 *            link 1           |                     |
 *   +--------------------> server                   |  link 2
 *   |                         |                     V
 *   |                         +-------------> service_2
 *   |        link 3
 *  client -------------------> server_via_unsafe_path -> service_3
 *
 * Among them,
 * 1. link-1 is very suitable for using SMC.
 * 2. link-2 is not suitable for using SMC, because the mode of this link is
 *    kind of short-link services.
 * 3. link-3 is also not suitable for using SMC, because the RDMA link is
 *    unavailable and needs to go through a long timeout before it can fallback
 *    to TCP.
 * To achieve this goal, we use a customized SMC ip strategy via smc_hs_ctrl.
 */
static void test_topo(void)
{
	struct bpf_smc *skel;
	int rc, map_fd;

	skel = bpf_smc__open_and_load();
	if (!ASSERT_OK_PTR(skel, "bpf_smc__open_and_load"))
		return;

	rc = bpf_smc__attach(skel);
	if (!ASSERT_OK(rc, "bpf_smc__attach"))
		goto fail;

	map_fd = bpf_map__fd(skel->maps.smc_policy_ip);
	if (!ASSERT_OK_FD(map_fd, "bpf_map__fd"))
		goto fail;

	/* Mock the process of transparent replacement, since we will modify
	 * protocol to ipproto_smc accropding to it via
	 * fmod_ret/update_socket_protocol.
	 */
	write_sysctl("/proc/sys/net/smc/hs_ctrl", "linkcheck");

	/* Configure ip strat */
	block_link(map_fd, CLIENT_IP, SERVER_IP_VIA_RISK_PATH);
	block_link(map_fd, SERVER_IP, SERVER_IP);

	/* should go with smc */
	run_link(CLIENT_IP, SERVER_IP, SERVICE_1);
	/* should go with smc fallback */
	run_link(SERVER_IP, SERVER_IP, SERVICE_2);

	ASSERT_EQ(skel->bss->smc_cnt, 2, "smc count");
	ASSERT_EQ(skel->bss->fallback_cnt, 1, "fallback count");

	/* should go with smc */
	run_link(CLIENT_IP, SERVER_IP, SERVICE_2);

	ASSERT_EQ(skel->bss->smc_cnt, 3, "smc count");
	ASSERT_EQ(skel->bss->fallback_cnt, 1, "fallback count");

	/* should go with smc fallback */
	run_link(CLIENT_IP, SERVER_IP_VIA_RISK_PATH, SERVICE_3);

	ASSERT_EQ(skel->bss->smc_cnt, 4, "smc count");
	ASSERT_EQ(skel->bss->fallback_cnt, 2, "fallback count");

fail:
	bpf_smc__destroy(skel);
}

void test_bpf_smc(void)
{
	if (!setup_smc()) {
		printf("setup for smc test failed, test SKIP:\n");
		test__skip();
		return;
	}

	if (test__start_subtest("topo"))
		test_topo();

	cleanup_ueid();
	cleanup_netns();
}
