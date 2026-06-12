// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <test_progs.h>
#include "cgroup_helpers.h"
#include "network_helpers.h"
#include "test_tcp_splice.skel.h"

#include <pthread.h>
#include <sys/wait.h>
#include <unistd.h>

#define MSG "hello rendezvous"
#define CLIENT_BANNER "client-banner"
#define SERVER_BANNER "server-banner"

struct recv_arg {
	int fd;
	char buf[64];
	int n;
	int err;
};

static void *recv_thread(void *p)
{
	struct recv_arg *a = p;

	a->n = recv(a->fd, a->buf, sizeof(a->buf) - 1, 0);
	a->err = errno;
	return NULL;
}

struct send_arg {
	int fd;
	const char *buf;
	size_t len;
	int n;
	int err;
};

static void *send_thread(void *p)
{
	struct send_arg *a = p;

	a->n = send(a->fd, a->buf, a->len, 0);
	a->err = errno;
	return NULL;
}

static int run_basic(int cgroup_fd, struct test_tcp_splice *skel)
{
	pthread_t tid;
	struct recv_arg a = {};
	int sfd = -1, cfd = -1, lfd = -1;
	int n, err = -1;

	lfd = start_server(AF_INET, SOCK_STREAM, NULL, 0, 0);
	if (!ASSERT_GE(lfd, 0, "start_server"))
		return -1;

	cfd = connect_to_fd(lfd, 0);
	if (!ASSERT_GE(cfd, 0, "connect_to_fd"))
		goto out;

	sfd = accept(lfd, NULL, NULL);
	if (!ASSERT_GE(sfd, 0, "accept"))
		goto out;

	/* Give both ESTABLISHED sock_ops callbacks a moment to run. */
	usleep(50 * 1000);

	if (!ASSERT_GE(skel->bss->pair_ok, 1, "splice paired"))
		goto out;
	ASSERT_EQ(skel->bss->pair_other_err, 0, "no unexpected pair errors");

	/* Drive the splice fast path: receiver enters recv() and publishes
	 * its bvec, sender then writes directly into it.
	 */
	a.fd = sfd;
	if (!ASSERT_OK(pthread_create(&tid, NULL, recv_thread, &a),
		       "pthread_create"))
		goto out;
	usleep(20 * 1000); /* let recv block */

	n = send(cfd, MSG, strlen(MSG), 0);
	ASSERT_EQ(n, (int)strlen(MSG), "send length");

	pthread_join(tid, NULL);
	ASSERT_EQ(a.n, (int)strlen(MSG), "recv length");
	a.buf[a.n > 0 ? a.n : 0] = 0;
	ASSERT_STREQ(a.buf, MSG, "recv contents");

	err = 0;
out:
	if (cfd >= 0)
		close(cfd);
	if (sfd >= 0)
		close(sfd);
	if (lfd >= 0)
		close(lfd);
	return err;
}

/* Bidirectional-write deadlock-avoidance test.
 *
 * Both sides issue send() before either calls recv(), the classic
 * pattern that used to deadlock under synchronous rendezvous (and
 * the actual cause of "kex_exchange_identification: write: Broken
 * pipe" with SSH on loopback). The bounded-wait fallback in
 * tcp_bpf_splice_sendmsg() must let both writes complete via the
 * normal TCP path within ~1 ms, and the banners must arrive intact
 * on the other side when recv() is called next.
 */
static int run_bidir_write(int cgroup_fd, struct test_tcp_splice *skel)
{
	pthread_t client_send_tid, server_send_tid;
	struct send_arg cs = { .buf = CLIENT_BANNER,
			       .len = sizeof(CLIENT_BANNER) - 1 };
	struct send_arg ss = { .buf = SERVER_BANNER,
			       .len = sizeof(SERVER_BANNER) - 1 };
	struct recv_arg cr = {}, sr = {};
	int sfd = -1, cfd = -1, lfd = -1;
	int err = -1;

	lfd = start_server(AF_INET, SOCK_STREAM, NULL, 0, 0);
	if (!ASSERT_GE(lfd, 0, "start_server"))
		return -1;
	cfd = connect_to_fd(lfd, 0);
	if (!ASSERT_GE(cfd, 0, "connect_to_fd"))
		goto out;
	sfd = accept(lfd, NULL, NULL);
	if (!ASSERT_GE(sfd, 0, "accept"))
		goto out;

	usleep(50 * 1000); /* let pair complete */

	/* Both sides write first, neither reads yet. Both must return
	 * within bounded time (no deadlock).
	 */
	cs.fd = cfd;
	ss.fd = sfd;
	if (!ASSERT_OK(pthread_create(&client_send_tid, NULL, send_thread, &cs),
		       "client send thread"))
		goto out;
	if (!ASSERT_OK(pthread_create(&server_send_tid, NULL, send_thread, &ss),
		       "server send thread"))
		goto out;

	pthread_join(client_send_tid, NULL);
	pthread_join(server_send_tid, NULL);
	ASSERT_EQ(cs.n, (int)cs.len, "client send length");
	ASSERT_EQ(ss.n, (int)ss.len, "server send length");

	/* Now read on each side - the bytes the peer wrote should have
	 * landed via the TCP fallback path.
	 */
	cr.fd = cfd;
	cr.n = recv(cr.fd, cr.buf, sizeof(cr.buf) - 1, 0);
	ASSERT_EQ(cr.n, (int)ss.len, "client recv length");
	cr.buf[cr.n > 0 ? cr.n : 0] = 0;
	ASSERT_STREQ(cr.buf, SERVER_BANNER, "client got server banner");

	sr.fd = sfd;
	sr.n = recv(sr.fd, sr.buf, sizeof(sr.buf) - 1, 0);
	ASSERT_EQ(sr.n, (int)cs.len, "server recv length");
	sr.buf[sr.n > 0 ? sr.n : 0] = 0;
	ASSERT_STREQ(sr.buf, CLIENT_BANNER, "server got client banner");

	err = 0;
out:
	if (cfd >= 0)
		close(cfd);
	if (sfd >= 0)
		close(sfd);
	if (lfd >= 0)
		close(lfd);
	return err;
}

void test_tcp_splice(void)
{
	struct test_tcp_splice *skel;
	int cgroup_fd, prog_fd;

	cgroup_fd = test__join_cgroup("/tcp_splice");
	if (!ASSERT_GE(cgroup_fd, 0, "join_cgroup"))
		return;

	skel = test_tcp_splice__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_load"))
		goto close_cgroup;

	prog_fd = bpf_program__fd(skel->progs.sockops_splice);
	if (!ASSERT_OK(bpf_prog_attach(prog_fd, cgroup_fd, BPF_CGROUP_SOCK_OPS, 0),
		       "attach sockops"))
		goto destroy_skel;

	if (test__start_subtest("basic"))
		run_basic(cgroup_fd, skel);
	if (test__start_subtest("bidir_write"))
		run_bidir_write(cgroup_fd, skel);

destroy_skel:
	test_tcp_splice__destroy(skel);
close_cgroup:
	close(cgroup_fd);
}
