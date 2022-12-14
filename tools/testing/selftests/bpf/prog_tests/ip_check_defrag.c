// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <net/if.h>
#include <network_helpers.h>
#include "ip_check_defrag.skel.h"

/*
 * This selftest spins up a client and an echo server, each in their own
 * network namespace. The server will receive fragmented messages which
 * the attached BPF prog should reassemble. We verify that reassembly
 * occurred by checking the original (fragmented) message is received
 * in whole.
 *
 * Topology:
 * =========
 *           NS0         |         NS1
 *                       |
 *         client        |       server
 *       ----------      |     ----------
 *       |  veth0  | --------- |  veth1  |
 *       ----------    peer    ----------
 *                       |
 *                       |       with bpf
 */

#define NS0		"defrag_ns0"
#define NS1		"defrag_ns1"
#define VETH0		"veth0"
#define VETH1		"veth1"
#define VETH0_ADDR	"172.16.1.100"
#define VETH1_ADDR	"172.16.1.200"
#define CLIENT_PORT	48878
#define SERVER_PORT	48879
#define MAGIC_MESSAGE	"THIS IS THE ORIGINAL MESSAGE, PLEASE REASSEMBLE ME"

static char log_buf[1024 * 1024];

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

/*
 * The following fragments are generated with this script invocation:
 *
 *	./generate_udp_fragments $VETH1_ADDR $CLIENT_PORT $SERVER_PORT $MAGIC_MESSAGE
 *
 * where the `$` indicates replacement with preprocessor macro.
 */
static uint8_t frag0[] = {
        0x45, 0x0, 0x0, 0x2c, 0x0, 0x1, 0x20, 0x0, 0x40, 0x11,
        0xac, 0xe8, 0x0, 0x0, 0x0, 0x0, 0xac, 0x10, 0x1, 0xc8,
        0xbe, 0xee, 0xbe, 0xef, 0x0, 0x3a, 0x0, 0x0, 0x54, 0x48,
        0x49, 0x53, 0x20, 0x49, 0x53, 0x20, 0x54, 0x48, 0x45, 0x20,
        0x4f, 0x52, 0x49, 0x47,
};
static uint8_t frag1[] = {
        0x45, 0x0, 0x0, 0x2c, 0x0, 0x1, 0x20, 0x3, 0x40, 0x11,
        0xac, 0xe5, 0x0, 0x0, 0x0, 0x0, 0xac, 0x10, 0x1, 0xc8,
        0x49, 0x4e, 0x41, 0x4c, 0x20, 0x4d, 0x45, 0x53, 0x53, 0x41,
        0x47, 0x45, 0x2c, 0x20, 0x50, 0x4c, 0x45, 0x41, 0x53, 0x45,
        0x20, 0x52, 0x45, 0x41,
};
static uint8_t frag2[] = {
        0x45, 0x0, 0x0, 0x1e, 0x0, 0x1, 0x0, 0x6, 0x40, 0x11,
        0xcc, 0xf0, 0x0, 0x0, 0x0, 0x0, 0xac, 0x10, 0x1, 0xc8,
        0x53, 0x53, 0x45, 0x4d, 0x42, 0x4c, 0x45, 0x20, 0x4d, 0x45,
};

static int setup_topology(void)
{
	SYS("ip netns add " NS0);
	SYS("ip netns add " NS1);
	SYS("ip link add " VETH0 " netns " NS0 " type veth peer name " VETH1 " netns " NS1);
	SYS("ip -net " NS0 " addr add " VETH0_ADDR "/24 dev " VETH0);
	SYS("ip -net " NS0 " link set dev " VETH0 " up");
	SYS("ip -net " NS1 " addr add " VETH1_ADDR "/24 dev " VETH1);
	SYS("ip -net " NS1 " link set dev " VETH1 " up");

	return 0;
fail:
	return -1;
}

static void cleanup_topology(void)
{
	SYS_NOFAIL("test -f /var/run/netns/" NS0 " && ip netns delete " NS0);
	SYS_NOFAIL("test -f /var/run/netns/" NS1 " && ip netns delete " NS1);
}

static int attach(struct ip_check_defrag *skel)
{
	LIBBPF_OPTS(bpf_tc_hook, tc_hook,
		    .attach_point = BPF_TC_INGRESS);
	LIBBPF_OPTS(bpf_tc_opts, tc_attach,
		    .prog_fd = bpf_program__fd(skel->progs.defrag));
	struct nstoken *nstoken;
	int err = -1;

	nstoken = open_netns(NS1);

	tc_hook.ifindex = if_nametoindex(VETH1);
	if (!ASSERT_OK(bpf_tc_hook_create(&tc_hook), "bpf_tc_hook_create"))
		goto out;

	if (!ASSERT_OK(bpf_tc_attach(&tc_hook, &tc_attach), "bpf_tc_attach"))
		goto out;

	err = 0;
out:
	close_netns(nstoken);
	return err;
}

static int send_frags(int client)
{
	struct sockaddr_storage saddr;
	struct sockaddr *saddr_p;
	socklen_t saddr_len;
	int err;

	saddr_p = (struct sockaddr*)&saddr;
	err = make_sockaddr(AF_INET, VETH1_ADDR, SERVER_PORT, &saddr, &saddr_len);
	if (!ASSERT_OK(err, "make_sockaddr"))
		return -1;

	err = sendto(client, frag0, sizeof(frag0), 0, saddr_p, saddr_len);
	if (!ASSERT_GE(err, 0, "sendto frag0"))
		return -1;

	err = sendto(client, frag1, sizeof(frag1), 0, saddr_p, saddr_len);
	if (!ASSERT_GE(err, 0, "sendto frag1"))
		return -1;

	err = sendto(client, frag2, sizeof(frag2), 0, saddr_p, saddr_len);
	if (!ASSERT_GE(err, 0, "sendto frag2"))
		return -1;

	return 0;
}

void test_bpf_ip_check_defrag_ok(void)
{
	struct network_helper_opts rx_opts = {
		.timeout_ms = 1000,
		.noconnect = true,
	};
	struct network_helper_opts tx_ops = {
		.timeout_ms = 1000,
		.type = SOCK_RAW,
		.proto = IPPROTO_RAW,
		.noconnect = true,
	};
	struct ip_check_defrag *skel;
	struct sockaddr_in caddr;
	struct nstoken *nstoken;
	int client_tx_fd = -1;
	int client_rx_fd = -1;
	socklen_t caddr_len;
	int srv_fd = -1;
	char buf[1024];
	int len, err;

	skel = ip_check_defrag__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	if (!ASSERT_OK(setup_topology(), "setup_topology"))
		goto out;

	if (!ASSERT_OK(attach(skel), "attach"))
		goto out;

	/* Start server in ns1 */
	nstoken = open_netns(NS1);
	if (!ASSERT_OK_PTR(nstoken, "setns ns1"))
		goto out;
	srv_fd = start_server(AF_INET, SOCK_DGRAM, NULL, SERVER_PORT, 0);
	close_netns(nstoken);
	if (!ASSERT_GE(srv_fd, 0, "start_server"))
		goto out;

	/* Open tx raw socket in ns0 */
	nstoken = open_netns(NS0);
	if (!ASSERT_OK_PTR(nstoken, "setns ns0"))
		goto out;
	client_tx_fd = connect_to_fd_opts(srv_fd, &tx_ops);
	close_netns(nstoken);
	if (!ASSERT_GE(client_tx_fd, 0, "connect_to_fd_opts"))
		goto out;

	/* Open rx socket in ns0 */
	nstoken = open_netns(NS0);
	if (!ASSERT_OK_PTR(nstoken, "setns ns0"))
		goto out;
	client_rx_fd = connect_to_fd_opts(srv_fd, &rx_opts);
	close_netns(nstoken);
	if (!ASSERT_GE(client_rx_fd, 0, "connect_to_fd_opts"))
		goto out;

	/* Bind rx socket to a premeditated port */
	memset(&caddr, 0, sizeof(caddr));
	caddr.sin_family = AF_INET;
	inet_pton(AF_INET, VETH0_ADDR, &caddr.sin_addr);
	caddr.sin_port = htons(CLIENT_PORT);
	nstoken = open_netns(NS0);
	err = bind(client_rx_fd, (struct sockaddr *)&caddr, sizeof(caddr));
	close_netns(nstoken);
	if (!ASSERT_OK(err, "bind"))
		goto out;

	/* Send message in fragments */
	if (!ASSERT_OK(send_frags(client_tx_fd), "send_frags"))
		goto out;

	if (!ASSERT_EQ(skel->bss->frags_seen, 3, "frags_seen"))
		goto out;

	if (!ASSERT_FALSE(skel->data->is_final_frag, "is_final_frag"))
		goto out;

	/* Receive reassembled msg on server and echo back to client */
	len = recvfrom(srv_fd, buf, sizeof(buf), 0, (struct sockaddr *)&caddr, &caddr_len);
	if (!ASSERT_GE(len, 0, "server recvfrom"))
		goto out;
	len = sendto(srv_fd, buf, len, 0, (struct sockaddr *)&caddr, caddr_len);
	if (!ASSERT_GE(len, 0, "server sendto"))
		goto out;

	/* Expect reassembed message to be echoed back */
	len = recvfrom(client_rx_fd, buf, sizeof(buf), 0, NULL, NULL);
	if (!ASSERT_EQ(len, sizeof(MAGIC_MESSAGE) - 1, "client short read"))
		goto out;

out:
	if (client_rx_fd != -1)
		close(client_rx_fd);
	if (client_tx_fd != -1)
		close(client_tx_fd);
	if (srv_fd != -1)
		close(srv_fd);
	cleanup_topology();
	ip_check_defrag__destroy(skel);
}

void test_bpf_ip_check_defrag_fail(void)
{
	const char *err_msg = "invalid mem access 'scalar'";
	LIBBPF_OPTS(bpf_object_open_opts, opts,
		    .kernel_log_buf = log_buf,
		    .kernel_log_size = sizeof(log_buf),
		    .kernel_log_level = 1);
	struct ip_check_defrag *skel;
	struct bpf_program *prog;
	int err;

	skel = ip_check_defrag__open_opts(&opts);
	if (!ASSERT_OK_PTR(skel, "ip_check_defrag__open_opts"))
		return;

	prog = bpf_object__find_program_by_name(skel->obj, "defrag_fail");
	if (!ASSERT_OK_PTR(prog, "bpf_object__find_program_by_name"))
		goto out;

	bpf_program__set_autoload(prog, true);

	err = ip_check_defrag__load(skel);
	if (!ASSERT_ERR(err, "ip_check_defrag__load must fail"))
		goto out;

	if (!ASSERT_OK_PTR(strstr(log_buf, err_msg), "expected error message")) {
		fprintf(stderr, "Expected: %s\n", err_msg);
		fprintf(stderr, "Verifier: %s\n", log_buf);
	}

out:
	ip_check_defrag__destroy(skel);
}

void test_bpf_ip_check_defrag(void)
{
	if (test__start_subtest("ok"))
		test_bpf_ip_check_defrag_ok();
	if (test__start_subtest("fail"))
		test_bpf_ip_check_defrag_fail();
}
