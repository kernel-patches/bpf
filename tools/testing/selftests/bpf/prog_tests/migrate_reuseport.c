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

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define NUM_SOCKS 5
#define LOCALHOST "127.0.0.1"
#define err_exit(condition, message)			      \
	do {						      \
		if (condition) {			      \
			perror("ERROR: " message " ");	      \
			exit(1);			      \
		}					      \
	} while (0)

__u64 server_fds[NUM_SOCKS];
int prog_fd, reuseport_map_fd, migrate_map_fd;


void setup_bpf(void)
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_map *reuseport_map, *migrate_map;
	int err;

	obj = bpf_object__open("test_migrate_reuseport_kern.o");
	err_exit(libbpf_get_error(obj), "opening BPF object file failed");

	err = bpf_object__load(obj);
	err_exit(err, "loading BPF object failed");

	prog = bpf_program__next(NULL, obj);
	err_exit(!prog, "loading BPF program failed");

	reuseport_map = bpf_object__find_map_by_name(obj, "reuseport_map");
	err_exit(!reuseport_map, "loading BPF reuseport_map failed");

	migrate_map = bpf_object__find_map_by_name(obj, "migrate_map");
	err_exit(!migrate_map, "loading BPF migrate_map failed");

	prog_fd = bpf_program__fd(prog);
	reuseport_map_fd = bpf_map__fd(reuseport_map);
	migrate_map_fd = bpf_map__fd(migrate_map);
}

void test_listen(void)
{
	struct sockaddr_in addr;
	socklen_t addr_len = sizeof(addr);
	int i, err, optval = 1, migrated_to = NUM_SOCKS - 1;
	__u64 value;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(80);
	inet_pton(AF_INET, LOCALHOST, &addr.sin_addr.s_addr);

	for (i = 0; i < NUM_SOCKS; i++) {
		server_fds[i] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		err_exit(server_fds[i] == -1, "socket() for listener sockets failed");

		err = setsockopt(server_fds[i], SOL_SOCKET, SO_REUSEPORT,
				 &optval, sizeof(optval));
		err_exit(err == -1, "setsockopt() for SO_REUSEPORT failed");

		if (i == 0) {
			err = setsockopt(server_fds[i], SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF,
					 &prog_fd, sizeof(prog_fd));
			err_exit(err == -1, "setsockopt() for SO_ATTACH_REUSEPORT_EBPF failed");
		}

		err = bind(server_fds[i], (struct sockaddr *)&addr, addr_len);
		err_exit(err == -1, "bind() failed");

		err = listen(server_fds[i], 32);
		err_exit(err == -1, "listen() failed");

		err = bpf_map_update_elem(reuseport_map_fd, &i, &server_fds[i], BPF_NOEXIST);
		err_exit(err == -1, "updating BPF reuseport_map failed");

		err = bpf_map_lookup_elem(reuseport_map_fd, &i, &value);
		err_exit(err == -1, "looking up BPF reuseport_map failed");

		printf("fd[%d] (cookie: %llu) -> fd[%d]\n", i, value, migrated_to);
		err = bpf_map_update_elem(migrate_map_fd, &value, &migrated_to, BPF_NOEXIST);
		err_exit(err == -1, "updating BPF migrate_map failed");
	}
}

void test_connect(void)
{
	struct sockaddr_in addr;
	socklen_t addr_len = sizeof(addr);
	int i, err, client_fd;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(80);
	inet_pton(AF_INET, LOCALHOST, &addr.sin_addr.s_addr);

	for (i = 0; i < NUM_SOCKS * 5; i++) {
		client_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		err_exit(client_fd == -1, "socket() for listener sockets failed");

		err = connect(client_fd, (struct sockaddr *)&addr, addr_len);
		err_exit(err == -1, "connect() failed");

		close(client_fd);
	}
}

void test_close(void)
{
	int i;

	for (i = 0; i < NUM_SOCKS - 1; i++)
		close(server_fds[i]);
}

void test_accept(void)
{
	struct sockaddr_in addr;
	socklen_t addr_len = sizeof(addr);
	int cnt, client_fd;

	fcntl(server_fds[NUM_SOCKS - 1], F_SETFL, O_NONBLOCK);

	for (cnt = 0; cnt < NUM_SOCKS * 5; cnt++) {
		client_fd = accept(server_fds[NUM_SOCKS - 1], (struct sockaddr *)&addr, &addr_len);
		err_exit(client_fd == -1, "accept() failed");
	}

	printf("%d accepted, %d is expected\n", cnt, NUM_SOCKS * 5);
}

int main(void)
{
	setup_bpf();
	test_listen();
	test_connect();
	test_close();
	test_accept();
	close(server_fds[NUM_SOCKS - 1]);
	return 0;
}
