// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Cloudflare
#include <error.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>

#include "test_progs.h"
#include "test_sockmap_msg_helpers.skel.h"
#include "sockmap_helpers.h"

#define TCP_REPAIR		19	/* TCP sock is under repair right now */

#define TCP_REPAIR_ON		1
#define TCP_REPAIR_OFF_NO_WP	-1	/* Turn off without window probes */

struct msg_test_opts {
	struct test_sockmap_msg_helpers *skel;
	int server;
	int client;
};

#define POP_END -1

static void pop_simple_send(struct msg_test_opts *opts, int start, int len)
{
	struct test_sockmap_msg_helpers *skel = opts->skel;
	char buf[] = "abcdefghijklmnopqrstuvwxyz";
	char recvbuf[sizeof(buf)];
	size_t sent, recv, cmp;

	skel->bss->pop = true;

	if (start == -1)
		start = sizeof(buf) - len - 1;

	skel->bss->pop_start = start;
	skel->bss->pop_len = len;

	sent = xsend(opts->client, buf, sizeof(buf), 0);
	if (sent < sizeof(buf))
		FAIL("xsend failed");

	ASSERT_OK(skel->bss->err, "pop error");

	recv = xrecv_nonblock(opts->server, recvbuf, sizeof(buf), 0);
	if (recv != sent - skel->bss->pop_len)
		FAIL("Received incorrect number number of bytes after pop");

	cmp = memcmp(&buf[0], &recvbuf[0], start);
	ASSERT_OK(cmp, "pop cmp start bytes failed");
	cmp = memcmp(&buf[start+len], &recvbuf[start], sizeof(buf) - start - len);
	ASSERT_OK(cmp, "pop cmp end bytes failed");
}

static void test_sockmap_pop(void)
{
	struct msg_test_opts opts;
	struct test_sockmap_msg_helpers *skel;
	int s, client, server;
	int err, map, prog;

	skel = test_sockmap_msg_helpers__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	map = bpf_map__fd(skel->maps.sock_map);
	prog = bpf_program__fd(skel->progs.msg_helpers);
	err = bpf_prog_attach(prog, map, BPF_SK_MSG_VERDICT, 0);
	if (!ASSERT_OK(err, "bpf_prog_attach"))
		goto out;

	s = socket_loopback(AF_INET, SOCK_STREAM);
	if (s < 0)
		goto out;

	err = create_pair(s, AF_INET, SOCK_STREAM, &client, &server);
	if (err < 0)
		goto close_loopback;

	err = add_to_sockmap(map, client, server);
	if (err < 0)
		goto close_sockets;

	opts.client = client;
	opts.server = server;
	opts.skel = skel;

	/* Pop from start */
	pop_simple_send(&opts, 0, 5);
	/* Pop from the middle */
	pop_simple_send(&opts, 10, 5);
	/* Pop from end */
	pop_simple_send(&opts, POP_END, 5);

close_sockets:
	close(client);
	close(server);
close_loopback:
	close(s);
out:
	test_sockmap_msg_helpers__destroy(skel);
}

static void test_sockmap_pop_errors(void)
{
	char buf[] = "abcdefghijklmnopqrstuvwxyz";
	struct test_sockmap_msg_helpers *skel;
	int i, recv, err, map, prog;
	char recvbuf[sizeof(buf)];
	int s, client, server;

	skel = test_sockmap_msg_helpers__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	map = bpf_map__fd(skel->maps.sock_map);
	prog = bpf_program__fd(skel->progs.msg_helpers);
	err = bpf_prog_attach(prog, map, BPF_SK_MSG_VERDICT, 0);
	if (!ASSERT_OK(err, "bpf_prog_attach"))
		goto out;

	s = socket_loopback(AF_INET, SOCK_STREAM);
	if (s < 0)
		goto out;

	err = create_pair(s, AF_INET, SOCK_STREAM, &client, &server);
	if (err < 0)
		goto close_loopback;

	err = add_to_sockmap(map, client, server);
	if (err < 0)
		goto close_sockets;

	skel->bss->pop = true;

	/* Pop larger than buffer */
	skel->bss->pop_start = 0;
	skel->bss->pop_len = sizeof(buf) + 1;
	xsend(client, buf, sizeof(buf), 0);
	ASSERT_ERR(skel->bss->err, "popping more bytes than msg did not throw an error");
	xrecv_nonblock(server, recvbuf, sizeof(recvbuf), 0);

	/* Pop past end of buffer */
	skel->bss->pop_start = sizeof(buf) - 5;
	skel->bss->pop_len = 10;
	xsend(client, buf, sizeof(buf), 0);
	ASSERT_ERR(skel->bss->err, "popping past end of msg did not throw an error");
	xrecv_nonblock(server, recvbuf, sizeof(recvbuf), 0);

	/* Pop larger than buffer on complex send */
	skel->bss->pop_start = 0;
	skel->bss->pop_len = 0;
	for (i = 0; i < 14; i++)
		xsend(client, buf, sizeof(buf), MSG_MORE);
	skel->bss->pop_start = 0;
	skel->bss->pop_len = sizeof(buf) * 32;
	xsend(client, buf, sizeof(buf), MSG_MORE);
	ASSERT_ERR(skel->bss->err, "popping more bytes than sg msg did not throw an error");
	i = 0;
	do {
		i++;
		recv = xrecv_nonblock(server, recvbuf, sizeof(recvbuf), 0);
	} while (recv > 0 && i < 15);

	/* Pop past end of complex send */
	skel->bss->pop_start = 0;
	skel->bss->pop_len = 0;
	for (i = 0; i < 14; i++)
		xsend(client, buf, sizeof(buf), MSG_MORE);
	skel->bss->pop_start = sizeof(buf) * 14;
	skel->bss->pop_len = sizeof(buf) + 1;
	xsend(client, buf, sizeof(buf), MSG_MORE);
	ASSERT_ERR(skel->bss->err, "popping past end of sg msg did not throw an error");
	i = 0;
	do {
		i++;
		recv = xrecv_nonblock(server, recvbuf, sizeof(recvbuf), 0);
	} while (recv > 0 && i < 15);

	/* Pop past end of complex send starting in middle of last sg */
	skel->bss->pop_start = 0;
	skel->bss->pop_len = 0;
	for (i = 0; i < 14; i++)
		xsend(client, buf, sizeof(buf), MSG_MORE);
	skel->bss->pop_start = (sizeof(buf) * 14) + sizeof(buf) - 5;
	skel->bss->pop_len = 10;
	xsend(client, buf, sizeof(buf), MSG_MORE);
	ASSERT_ERR(skel->bss->err, "popping past end from offset of sg msg did not throw an error");
	i = 0;
	do {
		i++;
		recv = xrecv_nonblock(server, recvbuf, sizeof(recvbuf), 0);
	} while (recv > 0 && i < 15);

close_sockets:
	close(client);
	close(server);
close_loopback:
	close(s);
out:
	test_sockmap_msg_helpers__destroy(skel);
}

void test_sockmap_msg_helpers(void)
{
	if (test__start_subtest("sockmap pop"))
		test_sockmap_pop();
	if (test__start_subtest("sockmap pop errors"))
		test_sockmap_pop_errors();
}
