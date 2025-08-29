// SPDX-License-Identifier: GPL-2.0
/* Copyright 2025 Google LLC */

#include <test_progs.h>
#include "sk_memcg.skel.h"
#include "network_helpers.h"

#define NR_SOCKETS	64
#define NR_SEND		64
#define BUF_SINGLE	1024
#define BUF_TOTAL	(BUF_SINGLE * NR_SEND)

struct test_case {
	char name[10]; /* protocols (%-9s) in /proc/net/protocols, see proto_seq_printf(). */
	int family;
	int type;
	int (*create_sockets)(struct test_case *test_case, int sk[], int len);
};

static int tcp_create_sockets(struct test_case *test_case, int sk[], int len)
{
	int server, i;

	server = start_server(test_case->family, test_case->type, NULL, 0, 0);
	ASSERT_GE(server, 0, "start_server_str");

	for (i = 0; i < len / 2; i++) {
		sk[i * 2] = connect_to_fd(server, 0);
		if (!ASSERT_GE(sk[i * 2], 0, "connect_to_fd"))
			return sk[i * 2];

		sk[i * 2 + 1] = accept(server, NULL, NULL);
		if (!ASSERT_GE(sk[i * 2 + 1], 0, "accept"))
			return sk[i * 2 + 1];
	}

	close(server);

	return 0;
}

static int udp_create_sockets(struct test_case *test_case, int sk[], int len)
{
	int i, err, rcvbuf = BUF_TOTAL;

	for (i = 0; i < len / 2; i++) {
		sk[i * 2] = start_server(test_case->family, test_case->type, NULL, 0, 0);
		if (!ASSERT_GE(sk[i * 2], 0, "start_server"))
			return sk[i * 2];

		sk[i * 2 + 1] = connect_to_fd(sk[i * 2], 0);
		if (!ASSERT_GE(sk[i * 2 + 1], 0, "connect_to_fd"))
			return sk[i * 2 + 1];

		err = connect_fd_to_fd(sk[i * 2], sk[i * 2 + 1], 0);
		if (!ASSERT_EQ(err, 0, "connect_fd_to_fd"))
			return err;

		err = setsockopt(sk[i * 2], SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(int));
		if (!ASSERT_EQ(err, 0, "setsockopt(SO_RCVBUF)"))
			return err;

		err = setsockopt(sk[i * 2 + 1], SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(int));
		if (!ASSERT_EQ(err, 0, "setsockopt(SO_RCVBUF)"))
			return err;
	}

	return 0;
}

static int get_memory_allocated(struct test_case *test_case)
{
	long memory_allocated = -1;
	char *line = NULL;
	size_t unused;
	FILE *f;

	f = fopen("/proc/net/protocols", "r");
	if (!ASSERT_OK_PTR(f, "fopen"))
		goto out;

	while (getline(&line, &unused, f) != -1) {
		unsigned int unused_0;
		int unused_1;
		int ret;

		if (strncmp(line, test_case->name, sizeof(test_case->name)))
			continue;

		ret = sscanf(line + sizeof(test_case->name), "%4u %6d  %6ld",
			     &unused_0, &unused_1, &memory_allocated);
		ASSERT_EQ(ret, 3, "sscanf");
		break;
	}

	ASSERT_NEQ(memory_allocated, -1, "get_memory_allocated");

	free(line);
	fclose(f);
out:
	return memory_allocated;
}

static int check_isolated(struct test_case *test_case, bool isolated)
{
	char buf[BUF_SINGLE] = {};
	long memory_allocated[2];
	int sk[NR_SOCKETS] = {};
	int err = -1, i, j;

	memory_allocated[0] = get_memory_allocated(test_case);
	if (!ASSERT_GE(memory_allocated[0], 0, "memory_allocated[0]"))
		goto out;

	err = test_case->create_sockets(test_case, sk, ARRAY_SIZE(sk));
	if (err)
		goto close;

	/* Must allocate pages >= net.core.mem_pcpu_rsv */
	for (i = 0; i < ARRAY_SIZE(sk); i++) {
		for (j = 0; j < NR_SEND; j++) {
			int bytes = send(sk[i], buf, sizeof(buf), 0);

			/* Avoid too noisy logs when something failed. */
			if (bytes != sizeof(buf))
				ASSERT_EQ(bytes, sizeof(buf), "send");
		}
	}

	memory_allocated[1] = get_memory_allocated(test_case);
	if (!ASSERT_GE(memory_allocated[1], 0, "memory_allocated[1]"))
		goto close;

	if (isolated) {
		ASSERT_LE(memory_allocated[1], memory_allocated[0] + 10, "isolated");
	} else {
		/* By default, net.core.mem_pcpu_rsv == 256 pages */
		ASSERT_GT(memory_allocated[1], memory_allocated[0] + 256, "not isolated");
	}

close:
	for (i = 0; i < ARRAY_SIZE(sk); i++)
		close(sk[i]);

	if (test_case->type == SOCK_DGRAM) {
		/* Give 150ms to let RCU destruct UDP sockets */
		usleep(150 * 1000);
	}
out:
	return err;
}

void run_test(struct test_case *test_case)
{
	struct sk_memcg *skel;
	int cgroup, err;

	skel = sk_memcg__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	cgroup = test__join_cgroup("/sk_memcg");
	if (!ASSERT_GE(cgroup, 0, "join_cgroup"))
		goto destroy_skel;

	err = check_isolated(test_case, false);
	if (!ASSERT_EQ(err, 0, "test_isolated(false)"))
		goto close_cgroup;

	skel->links.sock_create = bpf_program__attach_cgroup(skel->progs.sock_create, cgroup);
	if (!ASSERT_OK_PTR(skel->links.sock_create, "attach_cgroup(sock_create)"))
		goto close_cgroup;

	err = check_isolated(test_case, true);
	ASSERT_EQ(err, 0, "test_isolated(false)");

close_cgroup:
	close(cgroup);
destroy_skel:
	sk_memcg__destroy(skel);
}

struct test_case test_cases[] = {
	{
		.name = "TCP       ",
		.family = AF_INET,
		.type = SOCK_STREAM,
		.create_sockets = tcp_create_sockets,
	},
	{
		.name = "UDP       ",
		.family = AF_INET,
		.type = SOCK_DGRAM,
		.create_sockets = udp_create_sockets,
	},
	{
		.name = "TCPv6     ",
		.family = AF_INET6,
		.type = SOCK_STREAM,
		.create_sockets = tcp_create_sockets,
	},
	{
		.name = "UDPv6     ",
		.family = AF_INET6,
		.type = SOCK_DGRAM,
		.create_sockets = udp_create_sockets,
	},
};

void serial_test_sk_memcg(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(test_cases); i++) {
		test__start_subtest(test_cases[i].name);
		run_test(&test_cases[i]);
	}
}
