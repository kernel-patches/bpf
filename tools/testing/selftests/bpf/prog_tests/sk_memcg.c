// SPDX-License-Identifier: GPL-2.0
/* Copyright 2025 Google LLC */

#include <test_progs.h>
#include "sk_memcg.skel.h"
#include "network_helpers.h"

#define NR_SOCKETS	64
#define NR_SEND		128
#define BUF_SINGLE	1024
#define BUF_TOTAL	(BUF_SINGLE * NR_SEND)

struct test_case {
	char name[8];
	int family;
	int type;
	int (*create_sockets)(struct test_case *test_case, int sk[], int len);
	long (*get_memory_allocated)(struct test_case *test_case, struct sk_memcg *skel);
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

static long get_memory_allocated(struct test_case *test_case,
				 bool *activated, bool *stable,
				 long *memory_allocated)
{
	*stable = false;

	do {
		*activated = true;

		/* AF_INET and AF_INET6 share the same memory_allocated.
		 * tcp_init_sock() is called by AF_INET and AF_INET6,
		 * but udp_lib_init_sock() is inline.
		 */
		socket(AF_INET, test_case->type, 0);
	} while (!*stable);

	return *memory_allocated;
}

static long tcp_get_memory_allocated(struct test_case *test_case, struct sk_memcg *skel)
{
	return get_memory_allocated(test_case,
				    &skel->bss->tcp_activated,
				    &skel->bss->tcp_stable,
				    &skel->bss->tcp_memory_allocated);
}

static long udp_get_memory_allocated(struct test_case *test_case, struct sk_memcg *skel)
{
	return get_memory_allocated(test_case,
				    &skel->bss->udp_activated,
				    &skel->bss->udp_stable,
				    &skel->bss->udp_memory_allocated);
}

static int check_exclusive(struct test_case *test_case,
			   struct sk_memcg *skel, bool exclusive)
{
	char buf[BUF_SINGLE] = {};
	long memory_allocated[2];
	int sk[NR_SOCKETS] = {};
	int err, i, j;

	err = test_case->create_sockets(test_case, sk, ARRAY_SIZE(sk));
	if (err)
		goto close;

	memory_allocated[0] = test_case->get_memory_allocated(test_case, skel);

	/* allocate pages >= 1024 */
	for (i = 0; i < ARRAY_SIZE(sk); i++) {
		for (j = 0; j < NR_SEND; j++) {
			int bytes = send(sk[i], buf, sizeof(buf), 0);

			/* Avoid too noisy logs when something failed. */
			if (bytes != sizeof(buf)) {
				ASSERT_EQ(bytes, sizeof(buf), "send");
				if (bytes < 0) {
					err = bytes;
					goto close;
				}
			}
		}
	}

	memory_allocated[1] = test_case->get_memory_allocated(test_case, skel);

	if (exclusive)
		ASSERT_LE(memory_allocated[1], memory_allocated[0] + 10, "exclusive");
	else
		ASSERT_GT(memory_allocated[1], memory_allocated[0] + 1024, "not exclusive");

close:
	for (i = 0; i < ARRAY_SIZE(sk); i++)
		close(sk[i]);

	if (test_case->type == SOCK_DGRAM) {
		/* UDP recv queue is destroyed after RCU grace period.
		 * With one kern_sync_rcu(), memory_allocated[0] of the
		 * isoalted case often matches with memory_allocated[1]
		 * of the preceding non-exclusive case.
		 */
		kern_sync_rcu();
		kern_sync_rcu();
	}

	return err;
}

void run_test(struct test_case *test_case)
{
	struct nstoken *nstoken;
	struct sk_memcg *skel;
	int cgroup, err;

	skel = sk_memcg__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	skel->bss->nr_cpus = libbpf_num_possible_cpus();

	err = sk_memcg__attach(skel);
	if (!ASSERT_OK(err, "attach"))
		goto destroy_skel;

	cgroup = test__join_cgroup("/sk_memcg");
	if (!ASSERT_GE(cgroup, 0, "join_cgroup"))
		goto destroy_skel;

	err = make_netns("sk_memcg");
	if (!ASSERT_EQ(err, 0, "make_netns"))
		goto close_cgroup;

	nstoken = open_netns("sk_memcg");
	if (!ASSERT_OK_PTR(nstoken, "open_netns"))
		goto remove_netns;

	err = check_exclusive(test_case, skel, false);
	if (!ASSERT_EQ(err, 0, "test_exclusive(false)"))
		goto close_netns;

	err = write_sysctl("/proc/sys/net/core/memcg_exclusive", "1");
	if (!ASSERT_EQ(err, 0, "write_sysctl(1)"))
		goto close_netns;

	err = check_exclusive(test_case, skel, true);
	if (!ASSERT_EQ(err, 0, "test_exclusive(true by sysctl)"))
		goto close_netns;

	err = write_sysctl("/proc/sys/net/core/memcg_exclusive", "0");
	if (!ASSERT_EQ(err, 0, "write_sysctl(0)"))
		goto close_netns;

	skel->links.sock_create = bpf_program__attach_cgroup(skel->progs.sock_create, cgroup);
	if (!ASSERT_OK_PTR(skel->links.sock_create, "attach_cgroup(sock_create)"))
		goto close_netns;

	err = check_exclusive(test_case, skel, true);
	ASSERT_EQ(err, 0, "test_exclusive(true by bpf)");

close_netns:
	close_netns(nstoken);
remove_netns:
	remove_netns("sk_memcg");
close_cgroup:
	close(cgroup);
destroy_skel:
	sk_memcg__destroy(skel);
}

struct test_case test_cases[] = {
	{
		.name = "TCP  ",
		.family = AF_INET,
		.type = SOCK_STREAM,
		.create_sockets = tcp_create_sockets,
		.get_memory_allocated = tcp_get_memory_allocated,
	},
	{
		.name = "UDP  ",
		.family = AF_INET,
		.type = SOCK_DGRAM,
		.create_sockets = udp_create_sockets,
		.get_memory_allocated = udp_get_memory_allocated,
	},
	{
		.name = "TCPv6",
		.family = AF_INET6,
		.type = SOCK_STREAM,
		.create_sockets = tcp_create_sockets,
		.get_memory_allocated = tcp_get_memory_allocated,
	},
	{
		.name = "UDPv6",
		.family = AF_INET6,
		.type = SOCK_DGRAM,
		.create_sockets = udp_create_sockets,
		.get_memory_allocated = udp_get_memory_allocated,
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
