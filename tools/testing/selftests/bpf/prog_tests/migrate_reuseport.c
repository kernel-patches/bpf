// SPDX-License-Identifier: GPL-2.0
/*
 * Check if we can migrate child sockets.
 *
 *   1. call listen() for 5 server sockets.
 *   2. update a map to migrate all child sockets
 *        to the last server socket (migrate_map[cookie] = 4)
 *   3. call connect() for 25 client sockets.
 *   4. call shutdown() for first 4 server sockets
 *        and migrate the requests in the accept queue
 *        to the last server socket.
 *   5. call listen() for the second server socket.
 *   6. call shutdown() for the last server
 *        and migrate the requests in the accept queue
 *        to the second server socket.
 *   7. call listen() for the last server.
 *   8. call shutdown() for the second server
 *        and migrate the requests in the accept queue
 *        to the last server socket.
 *   9. call accept() for the last server socket.
 *
 * Author: Kuniyuki Iwashima <kuniyu@amazon.co.jp>
 */

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "test_progs.h"
#include "test_migrate_reuseport.skel.h"
#include "network_helpers.h"

#define NR_SERVERS 5
#define NR_CLIENTS (NR_SERVERS * 5)
#define MIGRATED_TO (NR_SERVERS - 1)

/* fastopenq->max_qlen and sk->sk_max_ack_backlog */
#define QLEN (NR_CLIENTS * 5)

#define MSG "Hello World\0"
#define MSGLEN 12

static struct migrate_reuseport_test_case {
	const char *name;
	__s64 servers[NR_SERVERS];
	__s64 clients[NR_CLIENTS];
	struct sockaddr_storage addr;
	socklen_t addrlen;
	int family;
	bool drop_ack;
	bool expire_synack_timer;
	bool fastopen;
} test_cases[] = {
	{
		.name = "IPv4 - TCP_ESTABLISHED - inet_csk_listen_stop",
		.family = AF_INET,
		.drop_ack = false,
		.expire_synack_timer = false,
		.fastopen = false,
	},
	{
		.name = "IPv4 - TCP_SYN_RECV - inet_csk_listen_stop",
		.family = AF_INET,
		.drop_ack = true,
		.expire_synack_timer = false,
		.fastopen = true,
	},
	{
		.name = "IPv4 - TCP_NEW_SYN_RECV - inet_csk_complete_hashdance",
		.family = AF_INET,
		.drop_ack = true,
		.expire_synack_timer = false,
		.fastopen = false,
	},
	{
		.name = "IPv4 - TCP_NEW_SYN_RECV - reqsk_timer_handler",
		.family = AF_INET,
		.drop_ack = true,
		.expire_synack_timer = true,
		.fastopen = false,
	},
	{
		.name = "IPv6 - TCP_ESTABLISHED - inet_csk_listen_stop",
		.family = AF_INET6,
		.drop_ack = false,
		.expire_synack_timer = false,
		.fastopen = false,
	},
	{
		.name = "IPv6 - TCP_SYN_RECV - inet_csk_listen_stop",
		.family = AF_INET6,
		.drop_ack = true,
		.expire_synack_timer = false,
		.fastopen = true,
	},
	{
		.name = "IPv6 - TCP_NEW_SYN_RECV - inet_csk_complete_hashdance",
		.family = AF_INET6,
		.drop_ack = true,
		.expire_synack_timer = false,
		.fastopen = false,
	},
	{
		.name = "IPv6 - TCP_NEW_SYN_RECV - reqsk_timer_handler",
		.family = AF_INET6,
		.drop_ack = true,
		.expire_synack_timer = true,
		.fastopen = false,
	}
};

static void init_fds(__s64 fds[], int len)
{
	int i;

	for (i = 0; i < len; i++)
		fds[i] = -1;
}

static void close_fds(__s64 fds[], int len)
{
	int i;

	for (i = 0; i < len; i++) {
		if (fds[i] != -1) {
			close(fds[i]);
			fds[i] = -1;
		}
	}
}

static int setup_fastopen(char *buf, int size, int *saved_len, bool restore)
{
	int err = 0, fd, len;

	fd = open("/proc/sys/net/ipv4/tcp_fastopen", O_RDWR);
	if (!ASSERT_NEQ(fd, -1, "open"))
		return -1;

	if (restore) {
		len = write(fd, buf, *saved_len);
		if (!ASSERT_EQ(len, *saved_len, "write - restore"))
			err = -1;
	} else {
		*saved_len = read(fd, buf, size);
		if (!ASSERT_LT(1, *saved_len, "read")) {
			err = -1;
			goto close;
		}

		err = lseek(fd, 0, SEEK_SET);
		if (!ASSERT_OK(err, "lseek"))
			goto close;

		/* (TFO_CLIENT_ENABLE | TFO_SERVER_ENABLE) */
		len = write(fd, "3", 1);
		if (!ASSERT_EQ(len, 1, "write - setup"))
			err = -1;
	}

close:
	close(fd);

	return err;
}

static int run_iptables(struct migrate_reuseport_test_case *test_case,
			bool add_rule)
{
	char buf[128];
	int err;

	sprintf(buf, "%s -%c OUTPUT -o lo -p tcp --dport %d --tcp-flags SYN,ACK ACK -j DROP",
		test_case->family == AF_INET ? "iptables" : "ip6tables",
		add_rule ? 'A' : 'D',
		ntohs(test_case->family == AF_INET ?
		      ((struct sockaddr_in *)&test_case->addr)->sin_port :
		      ((struct sockaddr_in6 *)&test_case->addr)->sin6_port));

	err = system(buf);

	return err == -1 ? err : WEXITSTATUS(err);
}

static int start_servers(struct migrate_reuseport_test_case *test_case,
			 struct test_migrate_reuseport *skel)
{
	int reuseport = 1, qlen = QLEN, migrated_to = MIGRATED_TO;
	int i, err, prog_fd, reuseport_map_fd, migrate_map_fd;
	__u64 value;

	prog_fd = bpf_program__fd(skel->progs.prog_migrate_reuseport);
	reuseport_map_fd = bpf_map__fd(skel->maps.reuseport_map);
	migrate_map_fd = bpf_map__fd(skel->maps.migrate_map);

	make_sockaddr(test_case->family,
		      test_case->family == AF_INET ? "127.0.0.1" : "::1", 0,
		      &test_case->addr, &test_case->addrlen);

	for (i = 0; i < NR_SERVERS; i++) {
		test_case->servers[i] = socket(test_case->family, SOCK_STREAM,
					       IPPROTO_TCP);
		if (!ASSERT_NEQ(test_case->servers[i], -1, "socket"))
			return -1;

		err = setsockopt(test_case->servers[i], SOL_SOCKET,
				 SO_REUSEPORT, &reuseport, sizeof(reuseport));
		if (!ASSERT_OK(err, "setsockopt - SO_REUSEPORT"))
			return -1;

		err = bind(test_case->servers[i],
			   (struct sockaddr *)&test_case->addr,
			   test_case->addrlen);
		if (!ASSERT_OK(err, "bind"))
			return -1;

		if (i == 0) {
			err = setsockopt(test_case->servers[i], SOL_SOCKET,
					 SO_ATTACH_REUSEPORT_EBPF,
					 &prog_fd, sizeof(prog_fd));
			if (!ASSERT_OK(err,
				       "setsockopt - SO_ATTACH_REUSEPORT_EBPF"))
				return -1;

			err = getsockname(test_case->servers[i],
					  (struct sockaddr *)&test_case->addr,
					  &test_case->addrlen);
			if (!ASSERT_OK(err, "getsockname"))
				return -1;
		}

		if (test_case->fastopen) {
			err = setsockopt(test_case->servers[i],
					 SOL_TCP, TCP_FASTOPEN,
					 &qlen, sizeof(qlen));
			if (!ASSERT_OK(err, "setsockopt - TCP_FASTOPEN"))
				return -1;
		}

		err = listen(test_case->servers[i], qlen);
		if (!ASSERT_OK(err, "listen"))
			return -1;

		value = (__u64)test_case->servers[i];
		err = bpf_map_update_elem(reuseport_map_fd, &i, &value,
					  BPF_NOEXIST);
		if (!ASSERT_OK(err, "bpf_map_update_elem - reuseport_map"))
			return -1;

		err = bpf_map_lookup_elem(reuseport_map_fd, &i, &value);
		if (!ASSERT_OK(err, "bpf_map_lookup_elem - reuseport_map"))
			return -1;

		err = bpf_map_update_elem(migrate_map_fd, &value, &migrated_to,
					  BPF_NOEXIST);
		if (!ASSERT_OK(err, "bpf_map_update_elem - migrate_map"))
			return -1;
	}

	return 0;
}

static int start_clients(struct migrate_reuseport_test_case *test_case)
{
	char buf[MSGLEN] = MSG;
	int i, err;

	for (i = 0; i < NR_CLIENTS; i++) {
		test_case->clients[i] = socket(test_case->family, SOCK_STREAM,
					       IPPROTO_TCP);
		if (!ASSERT_NEQ(test_case->clients[i], -1, "socket"))
			return -1;

		/* iptables only drops the final ACK, so clients will
		 * transition to TCP_ESTABLISHED immediately.
		 */
		err = settimeo(test_case->clients[i], 100);
		if (!ASSERT_OK(err, "settimeo"))
			return -1;

		if (test_case->fastopen) {
			int fastopen = 1;

			err = setsockopt(test_case->clients[i], IPPROTO_TCP,
					 TCP_FASTOPEN_CONNECT, &fastopen,
					 sizeof(fastopen));
			if (!ASSERT_OK(err,
				       "setsockopt - TCP_FASTOPEN_CONNECT"))
				return -1;
		}

		err = connect(test_case->clients[i],
			      (struct sockaddr *)&test_case->addr,
			      test_case->addrlen);
		if (!ASSERT_OK(err, "connect"))
			return -1;

		err = write(test_case->clients[i], buf, MSGLEN);
		if (!ASSERT_EQ(err, MSGLEN, "write"))
			return -1;
	}

	return 0;
}

static int migrate_dance(struct migrate_reuseport_test_case *test_case)
{
	int i, err;

	/* Migrate TCP_ESTABLISHED and TCP_SYN_RECV requests
	 * to the last listener based on eBPF.
	 */
	for (i = 0; i < MIGRATED_TO; i++) {
		err = shutdown(test_case->servers[i], SHUT_RDWR);
		if (!ASSERT_OK(err, "shutdown"))
			return -1;
	}

	/* No dance for TCP_NEW_SYN_RECV to migrate based on eBPF */
	if (!test_case->fastopen && test_case->drop_ack)
		return 0;

	/* Note that we use the second listener instead of the
	 * first one here.
	 *
	 * The fist listener is bind()ed with port 0 and,
	 * SOCK_BINDPORT_LOCK is not set to sk_userlocks, so
	 * calling listen() again will bind() the first listener
	 * on a new ephemeral port and detach it from the existing
	 * reuseport group.  (See: __inet_bind(), tcp_set_state())
	 *
	 * OTOH, the second one is bind()ed with a specific port,
	 * and SOCK_BINDPORT_LOCK is set. Thus, re-listen() will
	 * resurrect the listener on the existing reuseport group.
	 */
	err = listen(test_case->servers[1], QLEN);
	if (!ASSERT_OK(err, "listen"))
		return -1;

	/* Migrate from the last listener to the second one.
	 *
	 * All listeners were detached out of the reuseport_map,
	 * so migration will be done by kernel random pick from here.
	 */
	err = shutdown(test_case->servers[MIGRATED_TO], SHUT_RDWR);
	if (!ASSERT_OK(err, "shutdown"))
		return -1;

	/* Back to the existing reuseport group */
	err = listen(test_case->servers[MIGRATED_TO], QLEN);
	if (!ASSERT_OK(err, "listen"))
		return -1;

	/* Migrate back to the last one from the second one */
	err = shutdown(test_case->servers[1], SHUT_RDWR);
	if (!ASSERT_OK(err, "shutdown"))
		return -1;

	return 0;
}

static int count_requests(struct migrate_reuseport_test_case *test_case)
{
	struct sockaddr_storage addr;
	socklen_t len = sizeof(addr);
	char buf[MSGLEN];
	int cnt, client;

	settimeo(test_case->servers[MIGRATED_TO], 2000);

	for (cnt = 0; cnt < NR_CLIENTS; cnt++) {
		client = accept(test_case->servers[MIGRATED_TO],
				(struct sockaddr *)&addr, &len);
		if (!ASSERT_NEQ(client, -1, "accept"))
			goto out;

		memset(buf, 0, MSGLEN);

		read(client, &buf, MSGLEN);
		if (!ASSERT_STREQ(buf, MSG, "read")) {
			close(client);
			goto out;
		}

		close(client);
	}

out:
	return cnt;
}

static void run_test(struct migrate_reuseport_test_case *test_case,
		     struct test_migrate_reuseport *skel)
{
	bool added_rule = false;
	int err, saved_len;
	char buf[16];

	init_fds(test_case->servers, NR_SERVERS);
	init_fds(test_case->clients, NR_CLIENTS);

	if (test_case->fastopen) {
		memset(buf, 0, sizeof(buf));

		err = setup_fastopen(buf, sizeof(buf), &saved_len, false);
		if (!ASSERT_OK(err, "setup_fastopen - setup"))
			return;
	}

	err = start_servers(test_case, skel);
	if (!ASSERT_OK(err, "start_servers"))
		goto close_servers;

	if (test_case->drop_ack) {
		/* Drop the final ACK of the 3-way handshake and stick the
		 * in-flight requests on TCP_SYN_RECV or TCP_NEW_SYN_RECV.
		 */
		err = run_iptables(test_case, true);
		if (!ASSERT_OK(err, "run_iptables - add rule"))
			goto close_servers;

		added_rule = true;
	}

	err = start_clients(test_case);
	if (!ASSERT_OK(err, "start_clients"))
		goto close_clients;

	/* Migrate the requests in the accept queue only.
	 * TCP_NEW_SYN_RECV requests are not migrated at this point.
	 */
	err = migrate_dance(test_case);
	if (!ASSERT_OK(err, "migrate_dance"))
		goto close_clients;

	if (test_case->expire_synack_timer) {
		/* Wait for SYN+ACK timer to expire so that
		 * reqsk_timer_handler() migrates TCP_NEW_SYN_RECV requests.
		 */
		sleep(1);
	}

	if (test_case->drop_ack) {
		/* Resume 3WHS and migrate TCP_NEW_SYN_RECV requests */
		err = run_iptables(test_case, false);
		if (!ASSERT_OK(err, "run_iptables - delete rule"))
			goto close_clients;

		added_rule = false;
	}

	err = count_requests(test_case);
	ASSERT_EQ(err, NR_CLIENTS, test_case->name);

close_clients:
	close_fds(test_case->clients, NR_CLIENTS);

	if (added_rule) {
		err = run_iptables(test_case, false);
		ASSERT_OK(err, "run_iptables - clean up rule");
	}

close_servers:
	close_fds(test_case->servers, NR_SERVERS);

	if (test_case->fastopen) {
		err = setup_fastopen(buf, sizeof(buf), &saved_len, true);
		ASSERT_OK(err, "setup_fastopen - restore");
	}
}

void test_migrate_reuseport(void)
{
	struct test_migrate_reuseport *skel;
	int i;

	skel = test_migrate_reuseport__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	for (i = 0; i < ARRAY_SIZE(test_cases); i++)
		run_test(&test_cases[i], skel);

	test_migrate_reuseport__destroy(skel);
}
