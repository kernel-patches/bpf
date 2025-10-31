// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/*
 * BPF-based flow shaping
 *
 * The test brings up two veth in two isolated namespaces, attach some flow
 * shaping program onto it, and ensures that a manual speedtest maximum
 * value matches the rate set in the BPF shapers.
 */

#include <asm-generic/socket.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <math.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <bpf/libbpf.h>
#include <pthread.h>
#include "test_progs.h"
#include "network_helpers.h"
#include "test_tc_edt.skel.h"

#define SERVER_NS "tc-edt-server-ns"
#define CLIENT_NS "tc-edt-client-ns"
#define IP4_ADDR_VETH1 "192.168.1.1"
#define IP4_ADDR_VETH2 "192.168.1.2"
#define IP4_ADDR_VETH2_HEX 0xC0A80102

#define BUFFER_LEN		500
#define TIMEOUT_MS		2000
#define TEST_PORT		9000
#define TARGET_RATE_MBPS	5.0
#define RATE_ERROR_PERCENT	2.0

struct connection {
	int server_listen_fd;
	int server_conn_fd;
	int client_conn_fd;
};

static char tx_buffer[BUFFER_LEN], rx_buffer[BUFFER_LEN];
static bool tx_timeout;

static int start_server_listen(void)
{
	struct nstoken *nstoken = open_netns(SERVER_NS);
	int server_fd;

	if (!ASSERT_OK_PTR(nstoken, "enter server ns"))
		return -1;

	server_fd = start_server_str(AF_INET, SOCK_STREAM, IP4_ADDR_VETH2,
				     TEST_PORT, NULL);
	close_netns(nstoken);
	return server_fd;
}

static struct connection *setup_connection(void)
{
	int server_listen_fd, server_conn_fd, client_conn_fd;
	struct nstoken *nstoken;
	struct connection *conn;

	conn = malloc(sizeof(struct connection));
	if (!ASSERT_OK_PTR(conn, "allocate connection"))
		goto fail;
	server_listen_fd = start_server_listen();
	if (!ASSERT_OK_FD(server_listen_fd, "start server"))
		goto fail_free_conn;

	nstoken = open_netns(CLIENT_NS);
	if (!ASSERT_OK_PTR(nstoken, "enter client ns"))
		goto fail_close_server;

	client_conn_fd = connect_to_addr_str(AF_INET, SOCK_STREAM,
					     IP4_ADDR_VETH2, TEST_PORT, NULL);
	close_netns(nstoken);
	if (!ASSERT_OK_FD(client_conn_fd, "connect client"))
		goto fail_close_server;

	server_conn_fd = accept(server_listen_fd, NULL, NULL);
	if (!ASSERT_OK_FD(server_conn_fd, "accept client connection"))
		goto fail_close_client;

	conn->server_listen_fd = server_listen_fd;
	conn->server_conn_fd = server_conn_fd;
	conn->client_conn_fd = client_conn_fd;
	return conn;

fail_close_client:
	close(client_conn_fd);
fail_close_server:
	close(server_listen_fd);
fail_free_conn:
	free(conn);
fail:
	return NULL;
}

static void cleanup_connection(struct connection *conn)
{
	if (!conn)
		return;
	close(conn->client_conn_fd);
	close(conn->server_conn_fd);
	close(conn->server_listen_fd);
	free(conn);
}

static void *run_server(void *arg)
{
	int *fd = (int *)arg;
	int ret;

	while (!tx_timeout)
		ret = recv(*fd, rx_buffer, BUFFER_LEN, 0);

	return NULL;
}

static int read_rx_bytes(__u64 *result)
{
	struct nstoken *nstoken = open_netns(SERVER_NS);
	char line[512];
	FILE *fp;

	if (!ASSERT_OK_PTR(nstoken, "open server ns"))
		return -1;

	fp = fopen("/proc/net/dev", "r");
	if (!ASSERT_OK_PTR(fp, "open /proc/net/dev")) {
		close_netns(nstoken);
		return -1;
	}

	/* Skip the first two header lines */
	fgets(line, sizeof(line), fp);
	fgets(line, sizeof(line), fp);

	while (fgets(line, sizeof(line), fp)) {
		char name[32];
		__u64 rx_bytes = 0;

		if (sscanf(line, " %31[^:]: %llu", name, &rx_bytes) != 2)
			continue;

		if (strcmp(name, "veth2") == 0) {
			fclose(fp);
			close_netns(nstoken);
			*result = rx_bytes;
			return 0;
		}
	}

	fclose(fp);
	close_netns(nstoken);
	return -1;
}
static int setup(struct test_tc_edt *skel)
{
	struct nstoken *nstoken_client, *nstoken_server;
	int ret;

	if (!ASSERT_OK(make_netns(CLIENT_NS), "create client ns"))
		goto fail;
	if (!ASSERT_OK(make_netns(SERVER_NS), "create server ns"))
		goto fail_delete_client_ns;

	nstoken_client = open_netns(CLIENT_NS);
	if (!ASSERT_OK_PTR(nstoken_client, "open client ns"))
		goto fail_delete_server_ns;
	SYS(fail_close_client_ns, "ip link add veth1 type veth peer name %s",
	    "veth2 netns " SERVER_NS);
	SYS(fail_close_client_ns, "ip -4 addr add " IP4_ADDR_VETH1 "/24 dev veth1");
	SYS(fail_close_client_ns, "ip link set veth1 up");
	SYS(fail_close_client_ns, "tc qdisc add dev veth1 root fq");
	ret = tc_prog_attach("veth1", -1, bpf_program__fd(skel->progs.tc_prog));
	if (!ASSERT_OK(ret, "attach bpf prog"))
		goto fail_close_client_ns;

	nstoken_server = open_netns(SERVER_NS);
	if (!ASSERT_OK_PTR(nstoken_server, "enter server ns"))
		goto fail_close_client_ns;
	SYS(fail_close_server_ns, "ip -4 addr add " IP4_ADDR_VETH2 "/24 dev veth2");
	SYS(fail_close_server_ns, "ip link set veth2 up");
	close_netns(nstoken_server);
	close_netns(nstoken_client);

	return 0;

fail_close_server_ns:
	close_netns(nstoken_server);
fail_close_client_ns:
	close_netns(nstoken_client);
fail_delete_server_ns:
	remove_netns(SERVER_NS);
fail_delete_client_ns:
	remove_netns(CLIENT_NS);
fail:
	return -1;
}

static void cleanup(void)
{
	remove_netns(CLIENT_NS);
	remove_netns(SERVER_NS);
}

static void run_test(void)
{
	__u64 rx_bytes_start, rx_bytes_end;
	double rate_mbps, rate_error;
	pthread_t server_thread = 0;
	struct connection *conn;
	__u64 ts_start, ts_end;
	int ret;


	conn = setup_connection();
	if (!ASSERT_OK_PTR(conn, "setup client and server connection"))
		return;

	ret = pthread_create(&server_thread, NULL, run_server,
			     (void *)(&conn->server_conn_fd));
	if (!ASSERT_OK(ret, "start server rx thread"))
		goto end_cleanup_conn;
	if (!ASSERT_OK(read_rx_bytes(&rx_bytes_start), "read rx_bytes"))
		goto end_kill_thread;
	ts_start = get_time_ns();
	while (true) {
		send(conn->client_conn_fd, (void *)tx_buffer, BUFFER_LEN, 0);
		ts_end = get_time_ns();
		if ((ts_end - ts_start)/100000 >= TIMEOUT_MS) {
			tx_timeout = true;
			ret = read_rx_bytes(&rx_bytes_end);
			if (!ASSERT_OK(ret, "read_rx_bytes"))
				goto end_cleanup_conn;
			break;
		}
	}

	rate_mbps = (rx_bytes_end - rx_bytes_start) /
		    ((ts_end - ts_start) / 1000.0);
	rate_error =
		fabs((rate_mbps - TARGET_RATE_MBPS) * 100.0 / TARGET_RATE_MBPS);
	fprintf(stderr, "Rate:\t%f\nError:\t%f\n", rate_mbps, rate_error);

	ASSERT_LE(rate_error, RATE_ERROR_PERCENT,
		  "rate error is lower than threshold");

end_kill_thread:
	tx_timeout = true;
end_cleanup_conn:
	cleanup_connection(conn);
}

void test_tc_edt(void)
{
	struct test_tc_edt *skel;

	skel = test_tc_edt__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel open and load"))
		return;

	if (!ASSERT_OK(setup(skel), "global setup"))
		return;

	run_test();

	cleanup();
	test_tc_edt__destroy(skel);
}
