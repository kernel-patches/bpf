// SPDX-License-Identifier: GPL-2.0
#include <sys/un.h>

#include "test_progs.h"

#include "bind4_prog.skel.h"
#include "bind6_prog.skel.h"
#include "connect_unix_prog.skel.h"
#include "connect4_prog.skel.h"
#include "connect6_prog.skel.h"
#include "sendmsg4_prog.skel.h"
#include "sendmsg6_prog.skel.h"
#include "recvmsg4_prog.skel.h"
#include "recvmsg6_prog.skel.h"
#include "sendmsg_unix_prog.skel.h"
#include "recvmsg_unix_prog.skel.h"
#include "getsockname_unix_prog.skel.h"
#include "getpeername_unix_prog.skel.h"
#include "network_helpers.h"

#define TEST_IF_PREFIX          "test_sock_addr"
#define TEST_IPV4               "127.0.0.4"
#define TEST_IPV6               "::6"

#define SERV4_IP                "192.168.1.254"
#define SERV4_REWRITE_IP        "127.0.0.1"
#define SRC4_IP                 "172.16.0.1"
#define SRC4_REWRITE_IP         TEST_IPV4
#define SERV4_PORT              4040
#define SERV4_REWRITE_PORT      4444

#define SERV6_IP                "face:b00c:1234:5678::abcd"
#define SERV6_REWRITE_IP        "::1"
#define SERV6_V4MAPPED_IP       "::ffff:192.168.0.4"
#define SRC6_IP                 "::1"
#define SRC6_REWRITE_IP         TEST_IPV6
#define SERV6_PORT              6060
#define SERV6_REWRITE_PORT      6666

#define SERVUN_ADDRESS         "bpf_cgroup_unix_test"
#define SERVUN_REWRITE_ADDRESS "bpf_cgroup_unix_test_rewrite"
#define SRCUN_ADDRESS          "bpf_cgroup_unix_test_src"

enum sock_addr_test_type {
	SOCK_ADDR_TEST_BIND,
	SOCK_ADDR_TEST_CONNECT,
	SOCK_ADDR_TEST_SENDMSG,
	SOCK_ADDR_TEST_RECVMSG,
	SOCK_ADDR_TEST_GETSOCKNAME,
	SOCK_ADDR_TEST_GETPEERNAME,
};

typedef void *(*load_fn)(int cgroup_fd);
typedef void (*destroy_fn)(void *skel);

struct sock_addr_test {
	enum sock_addr_test_type type;
	const char *name;
	/* BPF prog properties */
	load_fn loadfn;
	destroy_fn destroyfn;
	/* Socket properties */
	int socket_family;
	int socket_type;
	/* IP:port pairs for BPF prog to override */
	const char *requested_addr;
	unsigned short requested_port;
	const char *expected_addr;
	unsigned short expected_port;
	const char *expected_src_addr;
};

#define BPF_SKEL_FUNCS(skel_name, prog_name) \
static void *skel_name##_load(int cgroup_fd) \
{ \
	struct skel_name *skel; \
	skel = skel_name##__open_and_load(); \
	if (!ASSERT_OK_PTR(skel, "skel_open")) \
		goto cleanup; \
	skel->links.prog_name = bpf_program__attach_cgroup( \
		skel->progs.prog_name, cgroup_fd); \
	if (!ASSERT_OK_PTR(skel->links.prog_name, "prog_attach")) \
		goto cleanup; \
	return skel; \
cleanup: \
	skel_name##__destroy(skel); \
	return NULL; \
} \
static void skel_name##_destroy(void *skel) \
{ \
	skel_name##__destroy(skel); \
}

BPF_SKEL_FUNCS(bind4_prog, bind_v4_prog);
BPF_SKEL_FUNCS(bind6_prog, bind_v6_prog);
BPF_SKEL_FUNCS(connect4_prog, connect_v4_prog);
BPF_SKEL_FUNCS(connect6_prog, connect_v6_prog);
BPF_SKEL_FUNCS(connect_unix_prog, connect_unix_prog);
BPF_SKEL_FUNCS(sendmsg4_prog, sendmsg_v4_prog);
BPF_SKEL_FUNCS(sendmsg6_prog, sendmsg_v6_prog);
BPF_SKEL_FUNCS(sendmsg_unix_prog, sendmsg_unix_prog);
BPF_SKEL_FUNCS(recvmsg4_prog, recvmsg4_prog);
BPF_SKEL_FUNCS(recvmsg6_prog, recvmsg6_prog);
BPF_SKEL_FUNCS(recvmsg_unix_prog, recvmsg_unix_prog);
BPF_SKEL_FUNCS(getsockname_unix_prog, getsockname_unix_prog);
BPF_SKEL_FUNCS(getpeername_unix_prog, getpeername_unix_prog);

static struct sock_addr_test tests[] = {
	/* bind - system calls */
	{
		SOCK_ADDR_TEST_BIND,
		"bind4: bind (stream)",
		bind4_prog_load,
		bind4_prog_destroy,
		AF_INET,
		SOCK_STREAM,
		SERV4_IP,
		SERV4_PORT,
		SERV4_REWRITE_IP,
		SERV4_REWRITE_PORT,
	},
	{
		SOCK_ADDR_TEST_BIND,
		"bind4: bind (dgram)",
		bind4_prog_load,
		bind4_prog_destroy,
		AF_INET,
		SOCK_DGRAM,
		SERV4_IP,
		SERV4_PORT,
		SERV4_REWRITE_IP,
		SERV4_REWRITE_PORT,
	},
	{
		SOCK_ADDR_TEST_BIND,
		"bind6: bind (stream)",
		bind6_prog_load,
		bind6_prog_destroy,
		AF_INET6,
		SOCK_STREAM,
		SERV6_IP,
		SERV6_PORT,
		SERV6_REWRITE_IP,
		SERV6_REWRITE_PORT,
	},
	{
		SOCK_ADDR_TEST_BIND,
		"bind6: bind (dgram)",
		bind6_prog_load,
		bind6_prog_destroy,
		AF_INET6,
		SOCK_DGRAM,
		SERV6_IP,
		SERV6_PORT,
		SERV6_REWRITE_IP,
		SERV6_REWRITE_PORT,
	},

	/* connect - system calls */
	{
		SOCK_ADDR_TEST_CONNECT,
		"connect4: connect (stream)",
		connect4_prog_load,
		connect4_prog_destroy,
		AF_INET,
		SOCK_STREAM,
		SERV4_IP,
		SERV4_PORT,
		SERV4_REWRITE_IP,
		SERV4_REWRITE_PORT,
		SRC4_REWRITE_IP,
	},
	{
		SOCK_ADDR_TEST_CONNECT,
		"connect4: connect (dgram)",
		connect4_prog_load,
		connect4_prog_destroy,
		AF_INET,
		SOCK_DGRAM,
		SERV4_IP,
		SERV4_PORT,
		SERV4_REWRITE_IP,
		SERV4_REWRITE_PORT,
		SRC4_REWRITE_IP,
	},
	{
		SOCK_ADDR_TEST_CONNECT,
		"connect6: connect (stream)",
		connect6_prog_load,
		connect6_prog_destroy,
		AF_INET6,
		SOCK_STREAM,
		SERV6_IP,
		SERV6_PORT,
		SERV6_REWRITE_IP,
		SERV6_REWRITE_PORT,
		SRC6_REWRITE_IP,
	},
	{
		SOCK_ADDR_TEST_CONNECT,
		"connect6: connect (dgram)",
		connect6_prog_load,
		connect6_prog_destroy,
		AF_INET6,
		SOCK_DGRAM,
		SERV6_IP,
		SERV6_PORT,
		SERV6_REWRITE_IP,
		SERV6_REWRITE_PORT,
		SRC6_REWRITE_IP,
	},
	{
		SOCK_ADDR_TEST_CONNECT,
		"connect_unix: connect (stream)",
		connect_unix_prog_load,
		connect_unix_prog_destroy,
		AF_UNIX,
		SOCK_STREAM,
		SERVUN_ADDRESS,
		0,
		SERVUN_REWRITE_ADDRESS,
		0,
		NULL,
	},

	/* sendmsg - system calls */
	{
		SOCK_ADDR_TEST_SENDMSG,
		"sendmsg4: sendmsg (dgram)",
		sendmsg4_prog_load,
		sendmsg4_prog_destroy,
		AF_INET,
		SOCK_DGRAM,
		SERV4_IP,
		SERV4_PORT,
		SERV4_REWRITE_IP,
		SERV4_REWRITE_PORT,
		SRC4_REWRITE_IP,
	},
	{
		SOCK_ADDR_TEST_SENDMSG,
		"sendmsg6: sendmsg (dgram)",
		sendmsg6_prog_load,
		sendmsg6_prog_destroy,
		AF_INET6,
		SOCK_DGRAM,
		SERV6_IP,
		SERV6_PORT,
		SERV6_REWRITE_IP,
		SERV6_REWRITE_PORT,
		SRC6_REWRITE_IP,
	},
	{
		SOCK_ADDR_TEST_SENDMSG,
		"sendmsg_unix: sendmsg (dgram)",
		sendmsg_unix_prog_load,
		sendmsg_unix_prog_destroy,
		AF_UNIX,
		SOCK_DGRAM,
		SERVUN_ADDRESS,
		0,
		SERVUN_REWRITE_ADDRESS,
		0,
		NULL,
	},

	/* recvmsg - system calls */
	{
		SOCK_ADDR_TEST_RECVMSG,
		"recvmsg4: recvfrom (dgram)",
		recvmsg4_prog_load,
		recvmsg4_prog_destroy,
		AF_INET,
		SOCK_DGRAM,
		SERV4_REWRITE_IP,
		SERV4_REWRITE_PORT,
		SERV4_REWRITE_IP,
		SERV4_REWRITE_PORT,
		SERV4_IP,
	},
	{
		SOCK_ADDR_TEST_RECVMSG,
		"recvmsg6: recvfrom (dgram)",
		recvmsg6_prog_load,
		recvmsg6_prog_destroy,
		AF_INET6,
		SOCK_DGRAM,
		SERV6_REWRITE_IP,
		SERV6_REWRITE_PORT,
		SERV6_REWRITE_IP,
		SERV6_REWRITE_PORT,
		SERV6_IP,
	},
	{
		SOCK_ADDR_TEST_RECVMSG,
		"recvmsg_unix: recvfrom (dgram)",
		recvmsg_unix_prog_load,
		recvmsg_unix_prog_destroy,
		AF_UNIX,
		SOCK_DGRAM,
		SERVUN_REWRITE_ADDRESS,
		0,
		SERVUN_REWRITE_ADDRESS,
		0,
		SERVUN_ADDRESS,
	},
	{
		SOCK_ADDR_TEST_RECVMSG,
		"recvmsg_unix: recvfrom (stream)",
		recvmsg_unix_prog_load,
		recvmsg_unix_prog_destroy,
		AF_UNIX,
		SOCK_STREAM,
		SERVUN_REWRITE_ADDRESS,
		0,
		SERVUN_REWRITE_ADDRESS,
		0,
		SERVUN_ADDRESS,
	},

	/* getsockname - system calls */
	{
		SOCK_ADDR_TEST_GETSOCKNAME,
		"getsockname_unix",
		getsockname_unix_prog_load,
		getsockname_unix_prog_destroy,
		AF_UNIX,
		SOCK_STREAM,
		SERVUN_ADDRESS,
		0,
		SERVUN_REWRITE_ADDRESS,
		0,
		NULL,
	},

	/* getpeername - system calls */
	{
		SOCK_ADDR_TEST_GETPEERNAME,
		"getpeername_unix",
		getpeername_unix_prog_load,
		getpeername_unix_prog_destroy,
		AF_UNIX,
		SOCK_STREAM,
		SERVUN_ADDRESS,
		0,
		SERVUN_REWRITE_ADDRESS,
		0,
		NULL,
	},
};

typedef int (*info_fn)(int, struct sockaddr *, socklen_t *);

static int cmp_addr(const struct sockaddr_storage *addr1, socklen_t addr1_len,
		    const struct sockaddr_storage *addr2, socklen_t addr2_len,
		    bool cmp_port)
{
	const struct sockaddr_in *four1, *four2;
	const struct sockaddr_in6 *six1, *six2;
	const struct sockaddr_un *un1, *un2;

	if (addr1->ss_family != addr2->ss_family)
		return -1;

	if (addr1_len != addr2_len)
		return -1;

	if (addr1->ss_family == AF_INET) {
		four1 = (const struct sockaddr_in *)addr1;
		four2 = (const struct sockaddr_in *)addr2;
		return !((four1->sin_port == four2->sin_port || !cmp_port) &&
			 four1->sin_addr.s_addr == four2->sin_addr.s_addr);
	} else if (addr1->ss_family == AF_INET6) {
		six1 = (const struct sockaddr_in6 *)addr1;
		six2 = (const struct sockaddr_in6 *)addr2;
		return !((six1->sin6_port == six2->sin6_port || !cmp_port) &&
			 !memcmp(&six1->sin6_addr, &six2->sin6_addr,
				 sizeof(struct in6_addr)));
	} else if (addr1->ss_family == AF_UNIX) {
		un1 = (const struct sockaddr_un *)addr1;
		un2 = (const struct sockaddr_un *)addr2;
		return memcmp(un1, un2, addr1_len);
	}

	return -1;
}

static int cmp_sock_addr(info_fn fn, int sock1,
			 const struct sockaddr_storage *addr2,
			 socklen_t addr2_len, bool cmp_port)
{
	struct sockaddr_storage addr1;
	socklen_t len1 = sizeof(addr1);

	memset(&addr1, 0, len1);
	if (fn(sock1, (struct sockaddr *)&addr1, (socklen_t *)&len1) != 0)
		return -1;

	return cmp_addr(&addr1, len1, addr2, addr2_len, cmp_port);
}

static int cmp_local_addr(int sock1, const struct sockaddr_storage *addr2,
			  socklen_t addr2_len, bool cmp_port)
{
	return cmp_sock_addr(getsockname, sock1, addr2, addr2_len, cmp_port);
}

static int cmp_peer_addr(int sock1, const struct sockaddr_storage *addr2,
			 socklen_t addr2_len, bool cmp_port)
{
	return cmp_sock_addr(getpeername, sock1, addr2, addr2_len, cmp_port);
}

static void test_bind(struct sock_addr_test *test)
{
	struct sockaddr_storage expected_addr;
	socklen_t expected_addr_len = sizeof(struct sockaddr_storage);
	int serv = -1, client = -1, err;

	serv = start_server(test->socket_family, test->socket_type,
			    test->requested_addr, test->requested_port, 0);
	if (!ASSERT_GE(serv, 0, "start_server"))
		goto cleanup;

	err = make_sockaddr(test->socket_family,
			    test->expected_addr, test->expected_port,
			    &expected_addr, &expected_addr_len);
	if (!ASSERT_EQ(err, 0, "make_sockaddr"))
		goto cleanup;

	err = cmp_local_addr(serv, &expected_addr, expected_addr_len, true);
	if (!ASSERT_EQ(err, 0, "cmp_local_addr"))
		goto cleanup;

	/* Try to connect to server just in case */
	client = connect_to_addr(&expected_addr, expected_addr_len, test->socket_type);
	if (!ASSERT_GE(client, 0, "connect_to_addr"))
		goto cleanup;

cleanup:
	if (client != -1)
		close(client);
	if (serv != -1)
		close(serv);
}

static void test_connect(struct sock_addr_test *test)
{
	struct sockaddr_storage addr, expected_addr, expected_src_addr;
	socklen_t addr_len = sizeof(struct sockaddr_storage),
		  expected_addr_len = sizeof(struct sockaddr_storage),
		  expected_src_addr_len = sizeof(struct sockaddr_storage);
	int serv = -1, client = -1, err;

	serv = start_server(test->socket_family, test->socket_type,
			    test->expected_addr, test->expected_port, 0);
	if (!ASSERT_GE(serv, 0, "start_server"))
		goto cleanup;

	err = make_sockaddr(test->socket_family, test->requested_addr, test->requested_port,
			    &addr, &addr_len);
	if (!ASSERT_EQ(err, 0, "make_sockaddr"))
		goto cleanup;

	client = connect_to_addr(&addr, addr_len, test->socket_type);
	if (!ASSERT_GE(client, 0, "connect_to_addr"))
		goto cleanup;

	err = make_sockaddr(test->socket_family, test->expected_addr, test->expected_port,
			    &expected_addr, &expected_addr_len);
	if (!ASSERT_EQ(err, 0, "make_sockaddr"))
		goto cleanup;

	if (test->expected_src_addr) {
		err = make_sockaddr(test->socket_family, test->expected_src_addr, 0,
				    &expected_src_addr, &expected_src_addr_len);
		if (!ASSERT_EQ(err, 0, "make_sockaddr"))
			goto cleanup;
	}

	err = cmp_peer_addr(client, &expected_addr, expected_addr_len, true);
	if (!ASSERT_EQ(err, 0, "cmp_peer_addr"))
		goto cleanup;

	if (test->expected_src_addr) {
		err = cmp_local_addr(client, &expected_src_addr, expected_src_addr_len, false);
		if (!ASSERT_EQ(err, 0, "cmp_local_addr"))
			goto cleanup;
	}
cleanup:
	if (client != -1)
		close(client);
	if (serv != -1)
		close(serv);
}

static void test_xmsg(struct sock_addr_test *test)
{
	struct sockaddr_storage addr, src_addr;
	socklen_t addr_len = sizeof(struct sockaddr_storage),
		  src_addr_len = sizeof(struct sockaddr_storage);
	struct msghdr hdr;
	struct iovec iov;
	char data = 'a';
	int serv = -1, client = -1, err;

	/* Unlike the other tests, here we test that we can rewrite the src addr
	 * with a recvmsg() hook.
	 */

	serv = start_server(test->socket_family, test->socket_type,
			    test->expected_addr, test->expected_port, 0);
	if (!ASSERT_GE(serv, 0, "start_server"))
		goto cleanup;

	client = socket(test->socket_family, test->socket_type, 0);
	if (!ASSERT_GE(client, 0, "socket"))
		goto cleanup;

	/* AF_UNIX sockets have to be bound to something to trigger the recvmsg bpf program. */
	if (test->socket_family == AF_UNIX) {
		err = make_sockaddr(AF_UNIX, SRCUN_ADDRESS, 0, &src_addr, &src_addr_len);
		if (!ASSERT_EQ(err, 0, "make_sockaddr"))
			goto cleanup;

		err = bind(client, (const struct sockaddr *) &src_addr, src_addr_len);
		if (!ASSERT_OK(err, "bind"))
			goto cleanup;
	}

	err = make_sockaddr(test->socket_family, test->requested_addr, test->requested_port,
			    &addr, &addr_len);
	if (!ASSERT_EQ(err, 0, "make_sockaddr"))
		goto cleanup;

	if (test->socket_type == SOCK_DGRAM) {
		memset(&iov, 0, sizeof(iov));
		iov.iov_base = &data;
		iov.iov_len = sizeof(data);

		memset(&hdr, 0, sizeof(hdr));
		hdr.msg_name = (void *)&addr;
		hdr.msg_namelen = addr_len;
		hdr.msg_iov = &iov;
		hdr.msg_iovlen = 1;

		err = sendmsg(client, &hdr, 0);
		if (!ASSERT_EQ(err, sizeof(data), "sendmsg"))
			goto cleanup;
	} else {
		/* Testing with connection-oriented sockets is only valid for
		 * recvmsg() tests.
		 */
		if (!ASSERT_EQ(test->type, SOCK_ADDR_TEST_RECVMSG, "recvmsg"))
			goto cleanup;

		err = connect(client, (const struct sockaddr *)&addr, addr_len);
		if (!ASSERT_OK(err, "connect"))
			goto cleanup;

		err = send(client, &data, sizeof(data), 0);
		if (!ASSERT_EQ(err, sizeof(data), "send"))
			goto cleanup;

		err = listen(serv, 0);
		if (!ASSERT_OK(err, "listen"))
			goto cleanup;

		err = accept(serv, NULL, NULL);
		if (!ASSERT_GE(err, 0, "accept"))
			goto cleanup;

		close(serv);
		serv = err;
	}

	addr_len = src_addr_len = sizeof(struct sockaddr_storage);

	err = recvfrom(serv, &data, sizeof(data), 0, (struct sockaddr *) &src_addr, &src_addr_len);
	if (!ASSERT_EQ(err, sizeof(data), "recvfrom"))
		goto cleanup;

	ASSERT_EQ(data, 'a', "data mismatch");

	if (test->expected_src_addr) {
		err = make_sockaddr(test->socket_family, test->expected_src_addr, 0,
				    &addr, &addr_len);
		if (!ASSERT_EQ(err, 0, "make_sockaddr"))
			goto cleanup;

		err = cmp_addr(&src_addr, src_addr_len, &addr, addr_len, false);
		if (!ASSERT_EQ(err, 0, "cmp_addr"))
			goto cleanup;
	}

cleanup:
	if (client != -1)
		close(client);
	if (serv != -1)
		close(serv);
}

static void test_getsockname(struct sock_addr_test *test)
{
	struct sockaddr_storage expected_addr;
	socklen_t expected_addr_len = sizeof(struct sockaddr_storage);
	int serv = -1, err;

	serv = start_server(test->socket_family, test->socket_type,
			    test->requested_addr, test->requested_port, 0);
	if (!ASSERT_GE(serv, 0, "start_server"))
		goto cleanup;

	err = make_sockaddr(test->socket_family,
			    test->expected_addr, test->expected_port,
			    &expected_addr, &expected_addr_len);
	if (!ASSERT_EQ(err, 0, "make_sockaddr"))
		goto cleanup;

	err = cmp_local_addr(serv, &expected_addr, expected_addr_len, true);
	if (!ASSERT_EQ(err, 0, "cmp_local_addr"))
		goto cleanup;

cleanup:
	if (serv != -1)
		close(serv);
}

static void test_getpeername(struct sock_addr_test *test)
{
	struct sockaddr_storage addr, expected_addr;
	socklen_t addr_len = sizeof(struct sockaddr_storage),
		  expected_addr_len = sizeof(struct sockaddr_storage);
	int serv = -1, client = -1, err;

	serv = start_server(test->socket_family, test->socket_type,
			    test->requested_addr, test->requested_port, 0);
	if (!ASSERT_GE(serv, 0, "start_server"))
		goto cleanup;

	err = make_sockaddr(test->socket_family, test->requested_addr, test->requested_port,
			    &addr, &addr_len);
	if (!ASSERT_EQ(err, 0, "make_sockaddr"))
		goto cleanup;

	client = connect_to_addr(&addr, addr_len, test->socket_type);
	if (!ASSERT_GE(client, 0, "connect_to_addr"))
		goto cleanup;

	err = make_sockaddr(test->socket_family, test->expected_addr, test->expected_port,
			    &expected_addr, &expected_addr_len);
	if (!ASSERT_EQ(err, 0, "make_sockaddr"))
		goto cleanup;

	err = cmp_peer_addr(client, &expected_addr, expected_addr_len, true);
	if (!ASSERT_EQ(err, 0, "cmp_peer_addr"))
		goto cleanup;

cleanup:
	if (client != -1)
		close(client);
	if (serv != -1)
		close(serv);
}

static int ping_once(int ipv, const char *addr)
{
	const char *ping_cmd_prefix = "ping -";

	if (!SYS_NOFAIL("type ping%d >/dev/null 2>&1", ipv))
		ping_cmd_prefix = "ping";

	return SYS_NOFAIL("%s%d -q -c 1 -W 1 %s >/dev/null 2>&1",
			  ping_cmd_prefix, ipv, addr);
}

static int setup_test_env(void)
{
	SYS(err, "ip link add dev %s1 type veth peer name %s2", TEST_IF_PREFIX,
	    TEST_IF_PREFIX);
	SYS(err, "ip link set %s1 up", TEST_IF_PREFIX);
	SYS(err, "ip link set %s2 up", TEST_IF_PREFIX);
	SYS(err, "ip -4 addr add %s/8 dev %s1", TEST_IPV4, TEST_IF_PREFIX);
	SYS(err, "ip -6 addr add %s/128 dev %s1", TEST_IPV6, TEST_IF_PREFIX);

	int i;

	for (i = 0; i < 5; i++) {
		if (!ping_once(4, TEST_IPV4) && !ping_once(6, TEST_IPV6))
			return 0;
	}

	ASSERT_FAIL("Timed out waiting for test IP to become available.");
err:
	return -1;
}

static void cleanup_test_env(void)
{
	SYS_NOFAIL("ip link del %s1 2>/dev/null", TEST_IF_PREFIX);
	SYS_NOFAIL("ip link del %s2 2>/dev/null", TEST_IF_PREFIX);
}

void test_sock_addr(void)
{
	int cgroup_fd = -1;
	void *skel;

	if (!ASSERT_OK(setup_test_env(), "setup_test_env"))
		goto cleanup;

	cgroup_fd = test__join_cgroup("/sock_addr");
	if (!ASSERT_GE(cgroup_fd, 0, "join_cgroup"))
		goto cleanup;

	for (size_t i = 0; i < ARRAY_SIZE(tests); ++i) {
		struct sock_addr_test *test = &tests[i];

		if (!test__start_subtest(test->name))
			continue;

		skel = test->loadfn(cgroup_fd);
		if (!skel)
			continue;

		switch (test->type) {
		/* Not exercised yet but we leave this code here for when the
		 * INET and INET6 sockaddr tests are migrated to this file in
		 * the future.
		 */
		case SOCK_ADDR_TEST_BIND:
			test_bind(test);
			break;
		case SOCK_ADDR_TEST_CONNECT:
			test_connect(test);
			break;
		case SOCK_ADDR_TEST_SENDMSG:
		case SOCK_ADDR_TEST_RECVMSG:
			test_xmsg(test);
			break;
		case SOCK_ADDR_TEST_GETSOCKNAME:
			test_getsockname(test);
			break;
		case SOCK_ADDR_TEST_GETPEERNAME:
			test_getpeername(test);
			break;
		default:
			ASSERT_TRUE(false, "Unknown sock addr test type");
			break;
		}

		test->destroyfn(skel);
	}

cleanup:
	if (cgroup_fd >= 0)
		close(cgroup_fd);
	cleanup_test_env();
}
