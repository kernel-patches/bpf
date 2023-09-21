// SPDX-License-Identifier: GPL-2.0
#include <sys/un.h>

#include "test_progs.h"

#include "connectun_prog.skel.h"
#include "sendmsgun_prog.skel.h"
#include "recvmsgun_prog.skel.h"
#include "getsocknameun_prog.skel.h"
#include "getpeernameun_prog.skel.h"
#include "network_helpers.h"

#define SERVUN_ADDRESS         "bpf_cgroup_unix_test"
#define SERVUN_REWRITE_ADDRESS "bpf_cgroup_unix_test_rewrite"
#define SRCUN_ADDRESS	       "bpf_cgroup_unix_test_src"

enum sock_addr_test_type {
	SOCK_ADDR_TEST_BIND,
	SOCK_ADDR_TEST_CONNECT,
	SOCK_ADDR_TEST_SENDMSG,
	SOCK_ADDR_TEST_RECVMSG,
	SOCK_ADDR_TEST_GETSOCKNAME,
	SOCK_ADDR_TEST_GETPEERNAME,
};

struct sock_addr_test;

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

static void *connectun_prog_load(int cgroup_fd)
{
	struct connectun_prog *skel;

	skel = connectun_prog__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		goto cleanup;

	skel->links.connectun_prog = bpf_program__attach_cgroup(
		skel->progs.connectun_prog, cgroup_fd);
	if (!ASSERT_OK_PTR(skel->links.connectun_prog, "prog_attach"))
		goto cleanup;

	return skel;
cleanup:
	connectun_prog__destroy(skel);
	return NULL;
}

static void connectun_prog_destroy(void *skel)
{
	connectun_prog__destroy(skel);
}

static void *sendmsgun_prog_load(int cgroup_fd)
{
	struct sendmsgun_prog *skel;

	skel = sendmsgun_prog__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		goto cleanup;

	skel->links.sendmsgun_prog = bpf_program__attach_cgroup(
		skel->progs.sendmsgun_prog, cgroup_fd);
	if (!ASSERT_OK_PTR(skel->links.sendmsgun_prog, "prog_attach"))
		goto cleanup;

	return skel;
cleanup:
	sendmsgun_prog__destroy(skel);
	return NULL;
}

static void sendmsgun_prog_destroy(void *skel)
{
	sendmsgun_prog__destroy(skel);
}

static void *recvmsgun_prog_load(int cgroup_fd)
{
	struct recvmsgun_prog *skel;

	skel = recvmsgun_prog__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		goto cleanup;

	skel->links.recvmsgun_prog = bpf_program__attach_cgroup(
		skel->progs.recvmsgun_prog, cgroup_fd);
	if (!ASSERT_OK_PTR(skel->links.recvmsgun_prog, "prog_attach"))
		goto cleanup;

	return skel;
cleanup:
	recvmsgun_prog__destroy(skel);
	return NULL;
}

static void recvmsgun_prog_destroy(void *skel)
{
	recvmsgun_prog__destroy(skel);
}

static void *getsocknameun_prog_load(int cgroup_fd)
{
	struct getsocknameun_prog *skel;

	skel = getsocknameun_prog__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		goto cleanup;

	skel->links.getsocknameun_prog = bpf_program__attach_cgroup(
		skel->progs.getsocknameun_prog, cgroup_fd);
	if (!ASSERT_OK_PTR(skel->links.getsocknameun_prog, "prog_attach"))
		goto cleanup;

	return skel;
cleanup:
	getsocknameun_prog__destroy(skel);
	return NULL;
}

static void getsocknameun_prog_destroy(void *skel)
{
	getsocknameun_prog__destroy(skel);
}

static void *getpeernameun_prog_load(int cgroup_fd)
{
	struct getpeernameun_prog *skel;

	skel = getpeernameun_prog__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		goto cleanup;

	skel->links.getpeernameun_prog = bpf_program__attach_cgroup(
		skel->progs.getpeernameun_prog, cgroup_fd);
	if (!ASSERT_OK_PTR(skel->links.getpeernameun_prog, "prog_attach"))
		goto cleanup;

	return skel;
cleanup:
	getpeernameun_prog__destroy(skel);
	return NULL;
}

static void getpeernameun_prog_destroy(void *skel)
{
	getpeernameun_prog__destroy(skel);
}

static struct sock_addr_test tests[] = {
	{
		SOCK_ADDR_TEST_CONNECT,
		"connectun",
		connectun_prog_load,
		connectun_prog_destroy,
		AF_UNIX,
		SOCK_STREAM,
		SERVUN_ADDRESS,
		0,
		SERVUN_REWRITE_ADDRESS,
		0,
		NULL,
	},
	{
		SOCK_ADDR_TEST_SENDMSG,
		"sendmsgun",
		sendmsgun_prog_load,
		sendmsgun_prog_destroy,
		AF_UNIX,
		SOCK_DGRAM,
		SERVUN_ADDRESS,
		0,
		SERVUN_REWRITE_ADDRESS,
		0,
		NULL,
	},
	{
		SOCK_ADDR_TEST_RECVMSG,
		"recvmsgun",
		recvmsgun_prog_load,
		recvmsgun_prog_destroy,
		AF_UNIX,
		SOCK_DGRAM,
		SERVUN_REWRITE_ADDRESS,
		0,
		SERVUN_REWRITE_ADDRESS,
		0,
		SERVUN_ADDRESS,
	},
	{
		SOCK_ADDR_TEST_GETSOCKNAME,
		"getsocknameun",
		getsocknameun_prog_load,
		getsocknameun_prog_destroy,
		AF_UNIX,
		SOCK_STREAM,
		SERVUN_ADDRESS,
		0,
		SERVUN_REWRITE_ADDRESS,
		0,
		NULL,
	},
	{
		SOCK_ADDR_TEST_GETPEERNAME,
		"getpeernameun",
		getpeernameun_prog_load,
		getpeernameun_prog_destroy,
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

	memset(&iov, 0, sizeof(iov));
	iov.iov_base = &data;
	iov.iov_len = sizeof(data);

	memset(&hdr, 0, sizeof(hdr));
	hdr.msg_name = (void *)&addr;
	hdr.msg_namelen = addr_len;
	hdr.msg_iov = &iov;
	hdr.msg_iovlen = 1;

	err = sendmsg(client, &hdr, 0);
	if (!ASSERT_EQ(err, sizeof(data), "sendto"))
		goto cleanup;

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

void test_sock_addr(void)
{
	int cgroup_fd = -1;
	void *skel;

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
}
