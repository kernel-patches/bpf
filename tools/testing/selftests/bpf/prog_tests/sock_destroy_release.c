// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "network_helpers.h"
#include "sock_destroy_release.skel.h"

#define TEST_NS "sock_destroy_release_netns"
#define BIND_ADDR4 "127.0.0.1"
#define BIND_ADDR6 "::1"
#define ANY_ADDR4 "0.0.0.0"
#define ANY_ADDR6 "::"

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
}

static void do_test(struct sock_destroy_release *skel, int sock_type,
		    int family, const char *bind_addr_str, const int bind_port)
{
	const char *addr = family == AF_INET ? BIND_ADDR4 : BIND_ADDR6;
	int listen_fd = -1, connect_fd = -1, accept_fd = -1;
	struct sockaddr_storage bind_addr;
	static const int port = 10001;
	socklen_t bind_addr_len;

	listen_fd = start_server(family, sock_type, addr, port, 0);
	if (!ASSERT_OK_FD(listen_fd, "start_server"))
		goto cleanup;

	connect_fd = client_socket(family, sock_type, NULL);
	if (!ASSERT_OK_FD(connect_fd, "client_socket"))
		goto cleanup;

	if (bind_addr_str) {
		if (!ASSERT_OK(make_sockaddr(family, bind_addr_str, bind_port,
					     &bind_addr, &bind_addr_len),
			       "make_sockaddr"))
			goto cleanup;
		if (!ASSERT_OK(bind(connect_fd, (struct sockaddr *)&bind_addr,
				    bind_addr_len), "bind"))
			goto cleanup;
	}

	if (!ASSERT_OK(connect_fd_to_fd(connect_fd, listen_fd, 0),
		       "connect_fd_to_fd"))
		goto cleanup;

	memset(&skel->bss->sk, 0, sizeof(skel->bss->sk));
	destroy(skel, connect_fd, sock_type);
	close(connect_fd);
	connect_fd = -1;
	ASSERT_EQ(ntohs(skel->bss->sk.dst_port), port, "dst_port");
	if (family == AF_INET) {
		ASSERT_EQ(ntohl(skel->bss->sk.dst_ip4), 0x7f000001, "dst_ip4");
	} else {
		ASSERT_EQ(skel->bss->sk.dst_ip6[0], 0, "dst_ip6[0]");
		ASSERT_EQ(skel->bss->sk.dst_ip6[1], 0, "dst_ip6[1]");
		ASSERT_EQ(skel->bss->sk.dst_ip6[2], 0, "dst_ip6[2]");
		ASSERT_EQ(ntohl(skel->bss->sk.dst_ip6[3]), 0x1, "dst_ip6[3]");
	}
cleanup:
	if (connect_fd >= 0)
		close(connect_fd);
	if (accept_fd >= 0)
		close(accept_fd);
	if (listen_fd >= 0)
		close(listen_fd);
}

static void do_tests(struct sock_destroy_release *skel, int sock_type,
		     int family, const char * const *bind_addrs,
		     size_t bind_addrs_len, const int *bind_ports,
		     size_t bind_ports_len)
{
	const char *protocol_name = sock_type == SOCK_STREAM ? "tcp" : "udp";
	const char *family_name = family == AF_INET ? "ipv4" : "ipv6";
	char name[256];

	for (size_t i = 0; i < bind_addrs_len; i++) {
		for (size_t j = 0; j < bind_ports_len; j++) {
			snprintf(name, sizeof(name), "%s/%s/destroy/%s:%d",
				 protocol_name, family_name, bind_addrs[i],
				 bind_ports[j]);
			if (test__start_subtest(name))
				do_test(skel, sock_type, family, bind_addrs[i],
					bind_ports[j]);
		}
	}
}

void test_sock_destroy_release(void)
{
	static const char * const bind4_addresses[] = {NULL, ANY_ADDR4,
						       BIND_ADDR4};
	static const char * const bind6_addresses[] = {NULL, ANY_ADDR6,
						       BIND_ADDR6};
	static const int bind_ports[] = {0, 10002};
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

	do_tests(skel, SOCK_STREAM, AF_INET, bind4_addresses,
		 ARRAY_SIZE(bind4_addresses), bind_ports,
		 ARRAY_SIZE(bind_ports));
	do_tests(skel, SOCK_STREAM, AF_INET6, bind6_addresses,
		 ARRAY_SIZE(bind6_addresses), bind_ports,
		 ARRAY_SIZE(bind_ports));
	do_tests(skel, SOCK_DGRAM, AF_INET, bind4_addresses,
		 ARRAY_SIZE(bind4_addresses), bind_ports,
		 ARRAY_SIZE(bind_ports));
	do_tests(skel, SOCK_DGRAM, AF_INET6, bind6_addresses,
		 ARRAY_SIZE(bind6_addresses), bind_ports,
		 ARRAY_SIZE(bind_ports));
done:
	if (nstoken)
		close_netns(nstoken);
	if (cgroup_fd >= 0)
		close(cgroup_fd);
	SYS_NOFAIL("ip netns del " TEST_NS);
	sock_destroy_release__destroy(skel);
}
