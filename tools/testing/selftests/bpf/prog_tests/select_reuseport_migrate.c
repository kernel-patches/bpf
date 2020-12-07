// SPDX-License-Identifier: GPL-2.0
/*
 * Check if we can migrate child sockets.
 *
 *   1. call listen() for 5 server sockets.
 *   2. update a map to migrate all child socket
 *        to the last server socket (migrate_map[cookie] = 4)
 *   3. call connect() for 25 client sockets.
 *   4. call close() for first 4 server sockets.
 *   5. call accept() for the last server socket.
 *
 * Author: Kuniyuki Iwashima <kuniyu@amazon.co.jp>
 */

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "test_progs.h"
#include "test_select_reuseport_migrate.skel.h"

#define ADDRESS "127.0.0.1"
#define PORT 80
#define NUM_SERVERS 5
#define NUM_CLIENTS (NUM_SERVERS * 5)


static int test_listen(struct test_select_reuseport_migrate *skel, int server_fds[])
{
	int i, err, optval = 1, migrated_to = NUM_SERVERS - 1;
	int prog_fd, reuseport_map_fd, migrate_map_fd;
	struct sockaddr_in addr;
	socklen_t addr_len;
	__u64 value;

	prog_fd = bpf_program__fd(skel->progs.prog_select_reuseport_migrate);
	reuseport_map_fd = bpf_map__fd(skel->maps.reuseport_map);
	migrate_map_fd = bpf_map__fd(skel->maps.migrate_map);

	addr_len = sizeof(addr);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT);
	inet_pton(AF_INET, ADDRESS, &addr.sin_addr.s_addr);

	for (i = 0; i < NUM_SERVERS; i++) {
		server_fds[i] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (CHECK_FAIL(server_fds[i] == -1))
			return -1;

		err = setsockopt(server_fds[i], SOL_SOCKET, SO_REUSEPORT,
				 &optval, sizeof(optval));
		if (CHECK_FAIL(err == -1))
			return -1;

		if (i == 0) {
			err = setsockopt(server_fds[i], SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF,
					 &prog_fd, sizeof(prog_fd));
			if (CHECK_FAIL(err == -1))
				return -1;
		}

		err = bind(server_fds[i], (struct sockaddr *)&addr, addr_len);
		if (CHECK_FAIL(err == -1))
			return -1;

		err = listen(server_fds[i], 32);
		if (CHECK_FAIL(err == -1))
			return -1;

		err = bpf_map_update_elem(reuseport_map_fd, &i, &server_fds[i], BPF_NOEXIST);
		if (CHECK_FAIL(err == -1))
			return -1;

		err = bpf_map_lookup_elem(reuseport_map_fd, &i, &value);
		if (CHECK_FAIL(err == -1))
			return -1;

		err = bpf_map_update_elem(migrate_map_fd, &value, &migrated_to, BPF_NOEXIST);
		if (CHECK_FAIL(err == -1))
			return -1;
	}

	return 0;
}

static int test_connect(int client_fds[])
{
	struct sockaddr_in addr;
	socklen_t addr_len;
	int i, err;

	addr_len = sizeof(addr);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT);
	inet_pton(AF_INET, ADDRESS, &addr.sin_addr.s_addr);

	for (i = 0; i < NUM_CLIENTS; i++) {
		client_fds[i] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (CHECK_FAIL(client_fds[i] == -1))
			return -1;

		err = connect(client_fds[i], (struct sockaddr *)&addr, addr_len);
		if (CHECK_FAIL(err == -1))
			return -1;
	}

	return 0;
}

static void test_close(int server_fds[], int num)
{
	int i;

	for (i = 0; i < num; i++)
		if (server_fds[i] > 0)
			close(server_fds[i]);
}

static int test_accept(int server_fd)
{
	struct sockaddr_in addr;
	socklen_t addr_len;
	int cnt, client_fd;

	fcntl(server_fd, F_SETFL, O_NONBLOCK);
	addr_len = sizeof(addr);

	for (cnt = 0; cnt < NUM_CLIENTS; cnt++) {
		client_fd = accept(server_fd, (struct sockaddr *)&addr, &addr_len);
		if (CHECK_FAIL(client_fd == -1))
			return -1;
	}

	return cnt;
}


void test_select_reuseport_migrate(void)
{
	struct test_select_reuseport_migrate *skel;
	int server_fds[NUM_SERVERS] = {0};
	int client_fds[NUM_CLIENTS] = {0};
	__u32 duration = 0;
	int err;

	skel = test_select_reuseport_migrate__open_and_load();
	if (CHECK_FAIL(!skel))
		goto destroy;

	err = test_listen(skel, server_fds);
	if (err)
		goto close_server;

	err = test_connect(client_fds);
	if (err)
		goto close_client;

	test_close(server_fds, NUM_SERVERS - 1);

	err = test_accept(server_fds[NUM_SERVERS - 1]);
	CHECK(err != NUM_CLIENTS,
	      "accept",
	      "expected (%d) != actual (%d)\n",
	      NUM_CLIENTS, err);

close_client:
	test_close(client_fds, NUM_CLIENTS);

close_server:
	test_close(server_fds, NUM_SERVERS);

destroy:
	test_select_reuseport_migrate__destroy(skel);
}
