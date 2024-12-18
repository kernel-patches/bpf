// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <linux/genetlink.h>
#include "bpf_smc.skel.h"

#ifndef IPPROTO_SMC
#define IPPROTO_SMC 256
#endif

#define CLIENT_IP			"127.0.0.1"
#define SERVER_IP			"127.0.1.0"
#define SERVER_IP_VIA_RISK_PATH	"127.0.2.0"

#define SERVICE_1	11234
#define SERVICE_2	22345
#define SERVICE_3	33456

enum {
	SMC_NETLINK_ADD_UEID = 10,
	SMC_NETLINK_REMOVE_UEID
};

enum {
	SMC_NLA_EID_TABLE_UNSPEC,
	SMC_NLA_EID_TABLE_ENTRY,    /* string */
};

struct smc_strat_ip_key {
	__u32  sip;
	__u32  dip;
};

struct smc_strat_ip_value {
	__u8	mode;
};

struct msgtemplate {
	struct nlmsghdr n;
	struct genlmsghdr g;
	char buf[1024];
};

#define GENLMSG_DATA(glh)	((void *)(NLMSG_DATA(glh) + GENL_HDRLEN))
#define GENLMSG_PAYLOAD(glh)	(NLMSG_PAYLOAD(glh, 0) - GENL_HDRLEN)
#define NLA_DATA(na)		((void *)((char *)(na) + NLA_HDRLEN))
#define NLA_PAYLOAD(len)	((len) - NLA_HDRLEN)

#define MAX_MSG_SIZE		1024

#define SMC_GENL_FAMILY_NAME	"SMC_GEN_NETLINK"
#define SMC_BPFTEST_UEID	"SMC-BPFTEST-UEID"

static uint16_t smc_nl_family_id = -1;
static bool running = true;

static int send_cmd(int fd, __u16 nlmsg_type, __u32 nlmsg_pid, __u16 nlmsg_flags,
			__u8 genl_cmd, __u16 nla_type,
			void *nla_data, int nla_len)
{
	struct nlattr *na;
	struct sockaddr_nl nladdr;
	int r, buflen;
	char *buf;

	struct msgtemplate msg = {0};

	msg.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	msg.n.nlmsg_type = nlmsg_type;
	msg.n.nlmsg_flags = nlmsg_flags;
	msg.n.nlmsg_seq = 0;
	msg.n.nlmsg_pid = nlmsg_pid;
	msg.g.cmd = genl_cmd;
	msg.g.version = 1;
	na = (struct nlattr *) GENLMSG_DATA(&msg);
	na->nla_type = nla_type;
	na->nla_len = nla_len + 1 + NLA_HDRLEN;
	memcpy(NLA_DATA(na), nla_data, nla_len);
	msg.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	buf = (char *) &msg;
	buflen = msg.n.nlmsg_len;
	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;

	while ((r = sendto(fd, buf, buflen, 0, (struct sockaddr *) &nladdr,
			   sizeof(nladdr))) < buflen) {
		if (r > 0) {
			buf += r;
			buflen -= r;
		} else if (errno != EAGAIN)
			return -1;
		}
	return 0;
}

static bool load_smc_module(void)
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SMC);

	if (!ASSERT_GE(fd, 0, "create ipproto_smc"))
		return false;
	close(fd);
	return true;
}

static bool create_netns(void)
{
	if (!ASSERT_OK(unshare(CLONE_NEWNET), "create netns"))
		return false;

	if (!ASSERT_OK(system("ip addr add 127.0.1.0/8 dev lo"), "add server node"))
		return false;

	if (!ASSERT_OK(system("ip addr add 127.0.2.0/8 dev lo"), "server via risk path"))
		return false;

	if (!ASSERT_OK(system("ip link set dev lo up"), "bring up lo"))
		return false;

	return true;
}

static bool get_smc_nl_family_id(void)
{
	struct sockaddr_nl nl_src;
	struct msgtemplate msg;
	struct nlattr *nl;
	int fd, ret;
	pid_t pid;

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (!ASSERT_GT(fd, 0, "nl_family socket"))
		return false;

	pid = getpid();

	memset(&nl_src, 0, sizeof(nl_src));
	nl_src.nl_family = AF_NETLINK;
	nl_src.nl_pid = pid;

	ret = bind(fd, (struct sockaddr *) &nl_src, sizeof(nl_src));
	if (!ASSERT_GE(ret, 0, "nl_family bind"))
		goto fail;

	ret = send_cmd(fd, GENL_ID_CTRL, pid,
		       NLM_F_REQUEST, CTRL_CMD_GETFAMILY,
		       CTRL_ATTR_FAMILY_NAME, (void *)SMC_GENL_FAMILY_NAME,
		       strlen(SMC_GENL_FAMILY_NAME));
	if (!ASSERT_EQ(ret, 0, "nl_family query"))
		goto fail;

	ret = recv(fd, &msg, sizeof(msg), 0);
	if (!ASSERT_FALSE(msg.n.nlmsg_type == NLMSG_ERROR || (ret < 0) ||
			  !NLMSG_OK((&msg.n), ret), "nl_family response"))
		goto fail;

	nl = (struct nlattr *) GENLMSG_DATA(&msg);
	nl = (struct nlattr *) ((char *) nl + NLA_ALIGN(nl->nla_len));
	if (!ASSERT_EQ(nl->nla_type, CTRL_ATTR_FAMILY_ID, "nl_family nla type"))
		goto fail;

	smc_nl_family_id = *(uint16_t *) NLA_DATA(nl);
	close(fd);
	return true;
fail:
	close(fd);
	return false;
}

static bool smc_ueid(int op)
{
	struct sockaddr_nl nl_src;
	struct msgtemplate msg;
	struct nlmsgerr *err;
	char test_ueid[32];
	int fd, ret;
	pid_t pid;

	/* UEID required */
	memset(test_ueid, '\x20', sizeof(test_ueid));
	memcpy(test_ueid, SMC_BPFTEST_UEID, strlen(SMC_BPFTEST_UEID));
	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (!ASSERT_GT(fd, 0, "ueid socket"))
		return false;

	pid = getpid();
	memset(&nl_src, 0, sizeof(nl_src));
	nl_src.nl_family = AF_NETLINK;
	nl_src.nl_pid = pid;

	ret = bind(fd, (struct sockaddr *) &nl_src, sizeof(nl_src));
	if (!ASSERT_GE(ret, 0, "ueid bind"))
		goto fail;

	ret = send_cmd(fd, smc_nl_family_id, pid,
		       NLM_F_REQUEST | NLM_F_ACK, op, SMC_NLA_EID_TABLE_ENTRY,
	(void *)test_ueid, sizeof(test_ueid));
	if (!ASSERT_EQ(ret, 0, "ueid cmd"))
		goto fail;

	ret = recv(fd, &msg, sizeof(msg), 0);
	if (!ASSERT_FALSE((ret < 0) || !NLMSG_OK((&msg.n), ret), "ueid response"))
		goto fail;

	if (msg.n.nlmsg_type == NLMSG_ERROR) {
		err = NLMSG_DATA(&msg);
		switch (op) {
		case SMC_NETLINK_REMOVE_UEID:
			if (!ASSERT_FALSE((err->error && err->error != -ENOENT), "ueid remove"))
				goto fail;
			break;
		case SMC_NETLINK_ADD_UEID:
			if (!ASSERT_EQ(err->error, 0, "ueid add"))
				goto fail;
			break;
		default:
			break;
		}
	}
	close(fd);
	return true;
fail:
	close(fd);
	return false;
}

static bool setup_smc(void)
{
	/* required smc module was loaded */
	if (!load_smc_module())
		return false;

	/* setup new netns to avoid make impact on other tests */
	if (!create_netns())
		return false;

	/* get smc nl id */
	if (!get_smc_nl_family_id())
		return false;

	/* clear and add ueid for bpftest */
	(void) smc_ueid(SMC_NETLINK_REMOVE_UEID);
	/* smc-loopback required ueid */
	if (!smc_ueid(SMC_NETLINK_ADD_UEID))
		return false;

	return true;
}

static void cleanup_smc(void)
{
	(void) smc_ueid(SMC_NETLINK_REMOVE_UEID);
}

static pthread_t create_service(const char *ip, int port, void *(*handler) (void *))
{
	struct sockaddr_in servaddr;
	pthread_t th;
	int server, rc;

	server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (!server)
		return (pthread_t)0;

	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(port);
	servaddr.sin_addr.s_addr = inet_addr(ip);

	rc = bind(server, &servaddr, sizeof(servaddr));
	if (!ASSERT_EQ(rc, 0, "server bind"))
		goto fail;

	rc = listen(server, 1024);
	if (!ASSERT_EQ(rc, 0, "server listen"))
		goto fail;

	rc = pthread_create(&th, NULL, handler, (void *)(intptr_t)server);
	if (!ASSERT_EQ(rc, 0, "pthread_create"))
		goto fail;

	return th;
fail:
	close(server);
	return (pthread_t)0;
}

static bool set_sock_timeout(int fd, int timeout_sec)
{
	struct timeval timeout = { .tv_sec = timeout_sec, };
	int rc;

	rc = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
	if (rc != 0)
		return false;

	rc = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	if (rc != 0)
		return false;

	return true;
}

static void req_once(const char *local, const char *remote, int port)
{
	struct sockaddr_in localaddr, servaddr;
	int client, rc, dummy = 0;

	client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (!client)
		return;

	/* 1 sec timeout for rcv and snd(connect) */
	if (!ASSERT_TRUE(set_sock_timeout(client, 1), "client sockopt"))
		goto fail;

	localaddr.sin_family = AF_INET;
	localaddr.sin_port = htons(0);
	localaddr.sin_addr.s_addr = inet_addr(local);

	rc = bind(client, &localaddr, sizeof(localaddr));
	if (!ASSERT_EQ(rc, 0, "client bind"))
		goto fail;

	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(port);
	servaddr.sin_addr.s_addr = inet_addr(remote);

	rc = connect(client, &servaddr, sizeof(servaddr));
	if (!ASSERT_EQ(rc, 0, "client connect"))
		goto fail;

	rc = send(client, &dummy, sizeof(dummy), 0);
	if (!ASSERT_EQ(rc, sizeof(dummy), "client query"))
		goto fail;

	rc = recv(client, &dummy, sizeof(dummy), 0);
	if (!ASSERT_EQ(rc, sizeof(dummy), "client response"))
		goto fail;

	close(client);
	return;
fail:
	close(client);
}

static void *service1(void *ctx)
{
	int fd = (int)(intptr_t)ctx;
	int cli, rc, dummy;

	/* 1 sec for accept timeout */
	if (!set_sock_timeout(fd, 1))
		goto finish;

	while (running) {
		cli = accept(fd, NULL, NULL);
		if (cli < 0)
			continue;

		if (!set_sock_timeout(cli, 1))
			goto skip;

		rc = recv(cli, &dummy, sizeof(dummy), 0);
		if (rc != sizeof(dummy))
			goto skip;

		/* service1 send a request to service2 */
		req_once(SERVER_IP, SERVER_IP, SERVICE_2);

		/* then echo dummy back to cli */
		rc = send(cli, &dummy, sizeof(dummy), 0);
		if (rc != sizeof(dummy))
			goto skip;
skip:
		close(cli);
	}
finish:
	close(fd);
	return NULL;
}

static void *service2(void *ctx)
{
	int fd = (int)(intptr_t)ctx;
	int cli, rc, dummy;

	/* 1 sec for accept timeout */
	if (!set_sock_timeout(fd, 1))
		goto finish;

	while (running) {
		cli = accept(fd, NULL, NULL);
		if (cli < 0)
			continue;

		if (!set_sock_timeout(cli, 1))
			goto skip;

		rc = recv(cli, &dummy, sizeof(dummy), 0);
		if (rc != sizeof(dummy))
			goto skip;

		/* then echo dummy back to cli */
		rc = send(cli, &dummy, sizeof(dummy), 0);
		if (rc != sizeof(dummy))
			goto skip;
skip:
		close(cli);
	}
finish:
	close(fd);
	return NULL;
}

static void *service3(void *ctx)
{
	return service2(ctx);
}

static void block_link(int map_fd, const char *src, const char *dst)
{
	struct smc_strat_ip_value val = { .mode = /* block */ 0 };
	struct smc_strat_ip_key key = {
		.sip = inet_addr(src),
		.dip = inet_addr(dst),
	};

	bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);
}

/*
 * This test describes a real-life service topology as follows:
 *
 *                             +-------------> service_1
 *            link1            |                     |
 *   +--------------------> server                   |  link 2
 *   |                         |                     V
 *   |                         +-------------> service_2
 *   |        link 3
 *  client -------------------> server_via_unsafe_path -> service_3
 *
 * Among them，
 * 1. link-1 is very suitable for using SMC.
 * 2. link-2 is not suitable for using SMC, because the mode of this link is kind of
 *     short-link services.
 * 3. link-3 is also not suitable for using SMC, because the RDMA link is unavailable and
 *     needs to go through a long timeout before it can fallback to TCP.
 *
 * To achieve this goal, we use a customized SMC ip strategy via smc_ops.
 */
static void test_topo(void)
{
	pthread_t service_1, service_2, service_3;
	struct bpf_smc *skel;
	int rc, map_fd;

	skel = bpf_smc__open_and_load();
	if (!ASSERT_OK_PTR(skel, "bpf_smc__open_and_load"))
		return;

	rc = bpf_smc__attach(skel);
	if (!ASSERT_EQ(rc, 0, "bpf_smc__attach"))
		goto fail;

	map_fd = bpf_map__fd(skel->maps.smc_strats_ip);
	if (!ASSERT_GT(map_fd, 0, "bpf_map__fd"))
		goto fail;

	/* Mock the process of transparent replacement, since we will modify protocol
	 * to ipproto_smc accropding to it via fmod_ret/update_socket_protocol.
	 */
	system("sysctl -w net.smc.ops=linkcheck");

	/* Configure ip strat */
	block_link(map_fd, CLIENT_IP, SERVER_IP_VIA_RISK_PATH);
	block_link(map_fd, SERVER_IP, SERVER_IP);
	close(map_fd);

	/* Load service */
	service_1 = create_service(SERVER_IP, SERVICE_1, service1);
	if (!ASSERT_NEQ(service_1, (pthread_t)0, "create service_1"))
		goto fail;

	service_2 = create_service(SERVER_IP, SERVICE_2, service2);
	if (!ASSERT_NEQ(service_2, (pthread_t)0, "create service_2")) {
		running = false;
		goto fail_service2;
	}

	service_3 = create_service(SERVER_IP_VIA_RISK_PATH, SERVICE_3, service3);
	if (!ASSERT_NEQ(service_3, (pthread_t)0, "create service_3")) {
		running = false;
		goto fail_service3;
	}

	/* Run client*/
	req_once(CLIENT_IP, SERVER_IP, SERVICE_1);

	ASSERT_EQ(skel->bss->smc_cnt, 2, "smc count");
	ASSERT_EQ(skel->bss->fallback_cnt, 1, "fallback count");

	req_once(CLIENT_IP, SERVER_IP, SERVICE_2);

	ASSERT_EQ(skel->bss->smc_cnt, 3, "smc count");
	ASSERT_EQ(skel->bss->fallback_cnt, 1, "fallback count");

	req_once(CLIENT_IP, SERVER_IP_VIA_RISK_PATH, SERVICE_3);

	ASSERT_EQ(skel->bss->smc_cnt, 4, "smc count");
	ASSERT_EQ(skel->bss->fallback_cnt, 2, "fallback count");

	/* We have set a timeout of 1 second for each accept */
	running = false;
	pthread_join(service_3, NULL);
fail_service3:
	pthread_join(service_2, NULL);
fail_service2:
	pthread_join(service_1, NULL);
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

	cleanup_smc();
}
