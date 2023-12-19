// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2023 Meta

#include <test_progs.h>
#include "network_helpers.h"
#include "sock_iter_batch.skel.h"

#define TEST_NS "sock_iter_batch_netns"

static const char expected_char = 'x';
static const int nr_soreuse = 4;

static void read_batch(struct bpf_program *prog, bool read_one)
{
	int iter_fd, i, nread, total_nread = 0;
	struct bpf_link *link;
	char b[nr_soreuse];

	link = bpf_program__attach_iter(prog, NULL);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_iter"))
		return;

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (!ASSERT_GE(iter_fd, 0, "bpf_iter_create")) {
		bpf_link__destroy(link);
		return;
	}

	do {
		nread = read(iter_fd, b, read_one ? 1 : nr_soreuse);
		if (nread <= 0)
			break;

		for (i = 0; i < nread; i++)
			ASSERT_EQ(b[i], expected_char, "b[i]");

		total_nread += nread;
	} while (total_nread <= nr_soreuse);

	ASSERT_EQ(nread, 0, "nread");
	ASSERT_EQ(total_nread, nr_soreuse, "total_nread");

	close(iter_fd);
	bpf_link__destroy(link);
}

static void do_test(int sock_type)
{
	struct sock_iter_batch *skel;
	int *fds, err;

	fds = start_reuseport_server(AF_INET6, sock_type, "::1", 0, 0,
				     nr_soreuse);
	if (!ASSERT_OK_PTR(fds, "start_reuseport_server"))
		return;

	skel = sock_iter_batch__open();
	if (!ASSERT_OK_PTR(skel, "sock_iter_batch__open"))
		goto done;

	skel->rodata->local_port = ntohs(get_socket_local_port(fds[0]));
	skel->rodata->expected_char = expected_char;

	err = sock_iter_batch__load(skel);
	if (!ASSERT_OK(err, "sock_iter_batch__load"))
		goto done;

	if (sock_type == SOCK_STREAM) {
		read_batch(skel->progs.iter_tcp_soreuse, true);
		read_batch(skel->progs.iter_tcp_soreuse, false);
	} else {
		read_batch(skel->progs.iter_udp_soreuse, true);
		read_batch(skel->progs.iter_udp_soreuse, false);
	}

done:
	sock_iter_batch__destroy(skel);
	free_fds(fds, nr_soreuse);
}

void test_sock_iter_batch(void)
{
	struct nstoken *nstoken = NULL;

	SYS_NOFAIL("ip netns del " TEST_NS " &> /dev/null");
	SYS(done, "ip netns add %s", TEST_NS);
	SYS(done, "ip -net %s link set dev lo up", TEST_NS);

	nstoken = open_netns(TEST_NS);
	if (!ASSERT_OK_PTR(nstoken, "open_netns"))
		goto done;

	if (test__start_subtest("tcp"))
		do_test(SOCK_STREAM);
	if (test__start_subtest("udp"))
		do_test(SOCK_DGRAM);

done:
	close_netns(nstoken);
	SYS_NOFAIL("ip netns del " TEST_NS " &> /dev/null");
}
