// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "network_helpers.h"
#include "sock_destroy_release.skel.h"

#define TEST_NS "sock_destroy_release_netns"

static __u64 socket_cookie(int fd)
{
	__u64 cookie;
	socklen_t cookie_len = sizeof(cookie);

	if (!ASSERT_OK(getsockopt(fd, SOL_SOCKET, SO_COOKIE, &cookie,
				  &cookie_len), "getsockopt(SO_COOKIE)"))
		return 0;
	return cookie;
}

static void destroy(struct sock_destroy_release *skel, int fd, int sock_type)
{
	__u64 cookie = socket_cookie(fd);
	struct bpf_link *link = NULL;
	int iter_fd = -1;
	int nread;
	__u64 out;

	skel->bss->abort_cookie = cookie;

	link = bpf_program__attach_iter(sock_type == SOCK_STREAM ?
					skel->progs.abort_tcp :
					skel->progs.abort_udp, NULL);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_iter"))
		goto done;

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (!ASSERT_OK_FD(iter_fd, "bpf_iter_create"))
		goto done;

	/* Delete matching socket. */
	nread = read(iter_fd, &out, sizeof(out));
	ASSERT_GE(nread, 0, "nread");
	if (nread)
		ASSERT_EQ(out, cookie, "cookie matches");
done:
	if (iter_fd >= 0)
		close(iter_fd);
	bpf_link__destroy(link);
	close(fd);
}

static void do_test(struct sock_destroy_release *skel, int sock_type,
		    int family)
{
	const char *addr = family == AF_INET ? "127.0.0.1" : "::1";
	int listen_fd = -1, connect_fd = -1;
	static const int port = 10001;

	listen_fd = start_server(family, sock_type, addr, port, 0);
	if (!ASSERT_OK_FD(listen_fd, "start_server"))
		goto cleanup;

	connect_fd = connect_to_fd(listen_fd, 0);
	if (!ASSERT_OK_FD(connect_fd, "connect_to_fd"))
		goto cleanup;

	memset(&skel->bss->sk, 0, sizeof(skel->bss->sk));
	destroy(skel, connect_fd, sock_type);
	connect_fd = -1;
	if (!ASSERT_EQ(ntohs(skel->bss->sk.dst_port), port, "dst_port"))
		goto cleanup;
	if (family == AF_INET) {
		if (!ASSERT_EQ(ntohl(skel->bss->sk.dst_ip4), 0x7f000001,
			       "dst_ip4"))
			goto cleanup;
	} else {
		if (!ASSERT_EQ(skel->bss->sk.dst_ip6[0], 0, "dst_ip6[0]"))
			goto cleanup;
		if (!ASSERT_EQ(skel->bss->sk.dst_ip6[1], 0, "dst_ip6[1]"))
			goto cleanup;
		if (!ASSERT_EQ(skel->bss->sk.dst_ip6[2], 0, "dst_ip6[2]"))
			goto cleanup;
		if (!ASSERT_EQ(ntohl(skel->bss->sk.dst_ip6[3]), 0x1,
			       "dst_ip6[3]"))
			goto cleanup;
	}
cleanup:
	if (connect_fd >= 0)
		close(connect_fd);
	if (listen_fd >= 0)
		close(listen_fd);
}

void test_sock_destroy_release(void)
{
	struct sock_destroy_release *skel = NULL;
	struct nstoken *nstoken = NULL;
	int cgroup_fd = -1;

	skel = sock_destroy_release__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto done;

	cgroup_fd = test__join_cgroup("/sock_destroy_release");
	if (!ASSERT_OK_FD(cgroup_fd, "join_cgroup"))
		goto done;

	skel->links.sock_release = bpf_program__attach_cgroup(
		skel->progs.sock_release, cgroup_fd);
	if (!ASSERT_OK_PTR(skel->links.sock_release, "attach_cgroup"))
		goto done;

	SYS_NOFAIL("ip netns del " TEST_NS);
	SYS(done, "ip netns add %s", TEST_NS);
	SYS(done, "ip -net %s link set dev lo up", TEST_NS);

	nstoken = open_netns(TEST_NS);
	if (!ASSERT_OK_PTR(nstoken, "open_netns"))
		goto done;

	if (test__start_subtest("tcp")) {
		do_test(skel, SOCK_STREAM, AF_INET);
		do_test(skel, SOCK_STREAM, AF_INET6);
	}
	if (test__start_subtest("udp")) {
		do_test(skel, SOCK_DGRAM, AF_INET);
		do_test(skel, SOCK_DGRAM, AF_INET6);
	}
done:
	if (nstoken)
		close_netns(nstoken);
	if (cgroup_fd >= 0)
		close(cgroup_fd);
	SYS_NOFAIL("ip netns del " TEST_NS);
	sock_destroy_release__destroy(skel);
}
