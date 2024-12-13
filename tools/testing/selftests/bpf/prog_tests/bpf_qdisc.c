#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <test_progs.h>

#include "network_helpers.h"
#include "bpf_qdisc_fifo.skel.h"

#ifndef ENOTSUPP
#define ENOTSUPP 524
#endif

#define LO_IFINDEX 1

static const unsigned int total_bytes = 10 * 1024 * 1024;
static int stop;

static void *server(void *arg)
{
	int lfd = (int)(long)arg, err = 0, fd;
	ssize_t nr_sent = 0, bytes = 0;
	char batch[1500];

	fd = accept(lfd, NULL, NULL);
	while (fd == -1) {
		if (errno == EINTR)
			continue;
		err = -errno;
		goto done;
	}

	if (settimeo(fd, 0)) {
		err = -errno;
		goto done;
	}

	while (bytes < total_bytes && !READ_ONCE(stop)) {
		nr_sent = send(fd, &batch,
			       MIN(total_bytes - bytes, sizeof(batch)), 0);
		if (nr_sent == -1 && errno == EINTR)
			continue;
		if (nr_sent == -1) {
			err = -errno;
			break;
		}
		bytes += nr_sent;
	}

	ASSERT_EQ(bytes, total_bytes, "send");

done:
	if (fd >= 0)
		close(fd);
	if (err) {
		WRITE_ONCE(stop, 1);
		return ERR_PTR(err);
	}
	return NULL;
}

static void do_test(char *qdisc)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = LO_IFINDEX,
			    .attach_point = BPF_TC_QDISC,
			    .parent = TC_H_ROOT,
			    .handle = 0x8000000,
			    .qdisc = qdisc);
	struct sockaddr_in6 sa6 = {};
	ssize_t nr_recv = 0, bytes = 0;
	int lfd = -1, fd = -1;
	pthread_t srv_thread;
	socklen_t addrlen = sizeof(sa6);
	void *thread_ret;
	char batch[1500];
	int err;

	WRITE_ONCE(stop, 0);

	err = bpf_tc_hook_create(&hook);
	if (!ASSERT_OK(err, "attach qdisc"))
		return;

	lfd = start_server(AF_INET6, SOCK_STREAM, NULL, 0, 0);
	if (!ASSERT_NEQ(lfd, -1, "socket")) {
		bpf_tc_hook_destroy(&hook);
		return;
	}

	fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (!ASSERT_NEQ(fd, -1, "socket")) {
		bpf_tc_hook_destroy(&hook);
		close(lfd);
		return;
	}

	if (settimeo(lfd, 0) || settimeo(fd, 0))
		goto done;

	err = getsockname(lfd, (struct sockaddr *)&sa6, &addrlen);
	if (!ASSERT_NEQ(err, -1, "getsockname"))
		goto done;

	/* connect to server */
	err = connect(fd, (struct sockaddr *)&sa6, addrlen);
	if (!ASSERT_NEQ(err, -1, "connect"))
		goto done;

	err = pthread_create(&srv_thread, NULL, server, (void *)(long)lfd);
	if (!ASSERT_OK(err, "pthread_create"))
		goto done;

	/* recv total_bytes */
	while (bytes < total_bytes && !READ_ONCE(stop)) {
		nr_recv = recv(fd, &batch,
			       MIN(total_bytes - bytes, sizeof(batch)), 0);
		if (nr_recv == -1 && errno == EINTR)
			continue;
		if (nr_recv == -1)
			break;
		bytes += nr_recv;
	}

	ASSERT_EQ(bytes, total_bytes, "recv");

	WRITE_ONCE(stop, 1);
	pthread_join(srv_thread, &thread_ret);
	ASSERT_OK(IS_ERR(thread_ret), "thread_ret");

done:
	close(lfd);
	close(fd);

	bpf_tc_hook_destroy(&hook);
	return;
}

static void test_fifo(void)
{
	struct bpf_qdisc_fifo *fifo_skel;
	struct bpf_link *link;

	fifo_skel = bpf_qdisc_fifo__open_and_load();
	if (!ASSERT_OK_PTR(fifo_skel, "bpf_qdisc_fifo__open_and_load"))
		return;

	link = bpf_map__attach_struct_ops(fifo_skel->maps.fifo);
	if (!ASSERT_OK_PTR(link, "bpf_map__attach_struct_ops")) {
		bpf_qdisc_fifo__destroy(fifo_skel);
		return;
	}

	do_test("bpf_fifo");

	bpf_link__destroy(link);
	bpf_qdisc_fifo__destroy(fifo_skel);
}

void test_bpf_qdisc(void)
{
	if (test__start_subtest("fifo"))
		test_fifo();
}
