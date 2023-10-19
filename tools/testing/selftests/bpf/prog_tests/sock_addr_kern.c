// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Google LLC. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "test_progs.h"

#include "cgroup_helpers.h"
#include "testing_helpers.h"
#include "bpf_util.h"
#include "network_helpers.h"
#include "sock_addr_helpers.h"

#define BIND    0
#define CONNECT 1
#define SENDMSG 2

struct sock_addr_kern_test;

typedef int (*load_fn)(const struct sock_addr_kern_test *test);

struct sock_addr_kern_test {
	const char *descr;
	/* BPF prog properties */
	load_fn loadfn;
	enum bpf_attach_type attach_type;
	/* Socket properties */
	int socket_family;
	int socket_type;
	/* IP:port pairs for BPF prog to override */
	const char *requested_ip;
	unsigned short requested_port;
	const char *expected_ip;
	unsigned short expected_port;
	const char *expected_src_ip;
};

static int ld_path(const struct sock_addr_kern_test *test, const char *path)
{
	return load_path(path, test->attach_type, false);
}

static int bind4_prog_load(const struct sock_addr_kern_test *test)
{
	return ld_path(test, BIND4_PROG_PATH);
}

static int bind6_prog_load(const struct sock_addr_kern_test *test)
{
	return ld_path(test, BIND6_PROG_PATH);
}

static int connect4_prog_load(const struct sock_addr_kern_test *test)
{
	return ld_path(test, CONNECT4_PROG_PATH);
}

static int connect6_prog_load(const struct sock_addr_kern_test *test)
{
	return ld_path(test, CONNECT6_PROG_PATH);
}

static int connect_unix_prog_load(const struct sock_addr_kern_test *test)
{
	return ld_path(test, "./connect_unix_prog.bpf.o");
}

static int sendmsg4_rw_c_prog_load(const struct sock_addr_kern_test *test)
{
	return ld_path(test, SENDMSG4_PROG_PATH);
}

static int sendmsg6_rw_c_prog_load(const struct sock_addr_kern_test *test)
{
	return ld_path(test, SENDMSG6_PROG_PATH);
}

static struct sock_addr_kern_test tests[] = {
	/* bind */
	{
		"bind4: ensure that kernel_bind does not overwrite the address "
		"(TCP)",
		bind4_prog_load,
		BPF_CGROUP_INET4_BIND,
		AF_INET,
		SOCK_STREAM,
		SERV4_IP,
		SERV4_PORT,
		SERV4_REWRITE_IP,
		SERV4_REWRITE_PORT,
	},
	{
		"bind4: ensure that kernel_bind does not overwrite the address "
		"(UDP)",
		bind4_prog_load,
		BPF_CGROUP_INET4_BIND,
		AF_INET,
		SOCK_DGRAM,
		SERV4_IP,
		SERV4_PORT,
		SERV4_REWRITE_IP,
		SERV4_REWRITE_PORT,
	},
	{
		"bind6: ensure that kernel_bind does not overwrite the address "
		"(TCP)",
		bind6_prog_load,
		BPF_CGROUP_INET6_BIND,
		AF_INET6,
		SOCK_STREAM,
		SERV6_IP,
		SERV6_PORT,
		SERV6_REWRITE_IP,
		SERV6_REWRITE_PORT,
	},
	{
		"bind6: ensure that kernel_bind does not overwrite the address "
		"(UDP)",
		bind6_prog_load,
		BPF_CGROUP_INET6_BIND,
		AF_INET6,
		SOCK_DGRAM,
		SERV6_IP,
		SERV6_PORT,
		SERV6_REWRITE_IP,
		SERV6_REWRITE_PORT,
	},

	/* connect */
	{
		"connect4: ensure that kernel_connect does not overwrite the "
		"address (TCP)",
		connect4_prog_load,
		BPF_CGROUP_INET4_CONNECT,
		AF_INET,
		SOCK_STREAM,
		SERV4_IP,
		SERV4_PORT,
		SERV4_REWRITE_IP,
		SERV4_REWRITE_PORT,
		SRC4_REWRITE_IP,
	},
	{
		"connect4: ensure that kernel_connect does not overwrite the "
		"address (UDP)",
		connect4_prog_load,
		BPF_CGROUP_INET4_CONNECT,
		AF_INET,
		SOCK_DGRAM,
		SERV4_IP,
		SERV4_PORT,
		SERV4_REWRITE_IP,
		SERV4_REWRITE_PORT,
		SRC4_REWRITE_IP,
	},
	{
		"connect6: ensure that kernel_connect does not overwrite the "
		"address (TCP)",
		connect6_prog_load,
		BPF_CGROUP_INET6_CONNECT,
		AF_INET6,
		SOCK_STREAM,
		SERV6_IP,
		SERV6_PORT,
		SERV6_REWRITE_IP,
		SERV6_REWRITE_PORT,
		SRC6_REWRITE_IP,
	},
	{
		"connect6: ensure that kernel_connect does not overwrite the "
		"address (UDP)",
		connect6_prog_load,
		BPF_CGROUP_INET6_CONNECT,
		AF_INET6,
		SOCK_DGRAM,
		SERV6_IP,
		SERV6_PORT,
		SERV6_REWRITE_IP,
		SERV6_REWRITE_PORT,
		SRC6_REWRITE_IP,
	},
	{
		"connect_unix: ensure that kernel_connect does not overwrite "
		"the address",
		connect_unix_prog_load,
		BPF_CGROUP_UNIX_CONNECT,
		AF_UNIX,
		SOCK_STREAM,
		"bpf_cgroup_unix_test",
		0,
		"bpf_cgroup_unix_test_rewrite",
		0,
		NULL,
	},

	/* sendmsg */
	{
		"sendmsg4: ensure that kernel_sendmsg does not overwrite the "
		"address (UDP)",
		sendmsg4_rw_c_prog_load,
		BPF_CGROUP_UDP4_SENDMSG,
		AF_INET,
		SOCK_DGRAM,
		SERV4_IP,
		SERV4_PORT,
		SERV4_REWRITE_IP,
		SERV4_REWRITE_PORT,
		SRC4_REWRITE_IP,
	},
	{
		"sendmsg6: ensure that kernel_sendmsg does not overwrite the "
		"address (UDP)",
		sendmsg6_rw_c_prog_load,
		BPF_CGROUP_UDP6_SENDMSG,
		AF_INET6,
		SOCK_DGRAM,
		SERV6_IP,
		SERV6_PORT,
		SERV6_REWRITE_IP,
		SERV6_REWRITE_PORT,
		SRC6_REWRITE_IP,
	},
	{
		"sendmsg_unix: ensure that kernel_sendmsg does not overwrite "
		"the address",
		connect_unix_prog_load,
		BPF_CGROUP_UNIX_SENDMSG,
		AF_UNIX,
		SOCK_DGRAM,
		"bpf_cgroup_unix_test",
		0,
		"bpf_cgroup_unix_test_rewrite",
		0,
		NULL,
	},
};

struct sock_addr_testmod_results {
	bool success;
	struct sockaddr_storage addr;
	struct sockaddr_storage sock_name;
	struct sockaddr_storage peer_name;
};

static int load_mod(const struct sock_addr_kern_test *test, int op)
{
	char params_str[512];

	if (sprintf(params_str, "ip=%s port=%hu af=%d type=%d op=%d",
		    test->requested_ip, test->requested_port,
		    test->socket_family, test->socket_type, op) < 0)
		return -1;

	if (load_bpf_sock_addr_testmod(params_str, false))
		return -1;

	return 0;
}

static int unload_mod()
{
	return unload_bpf_sock_addr_testmod(false);
}

static int read_result(const char *path, void *val, size_t len)
{
	FILE *f;
	int err;

	f = fopen(path, "r");
	if (!f)
		goto err;

	err = fread(val, 1, len, f);
	if (err != len)
		goto err;

	err = 0;
	goto out;

err:
	err = -1;
out:
	if (f)
		fclose(f);

	return err;
}

static int read_mod_results(struct sock_addr_testmod_results *results)
{
	char success[2];
	int err;

	if (read_result("/sys/kernel/debug/sock_addr_testmod/success", success,
			sizeof(success)))
		goto err;

	switch (success[0]) {
	case 'N':
		results->success = false;
		break;
	case 'Y':
		results->success = true;
		break;
	default:
		goto err;
	}

	if (read_result("/sys/kernel/debug/sock_addr_testmod/addr",
			&results->addr, sizeof(results->addr)))
		goto err;

	if (read_result("/sys/kernel/debug/sock_addr_testmod/sock_name",
			&results->sock_name, sizeof(results->sock_name)))
		goto err;

	if (read_result("/sys/kernel/debug/sock_addr_testmod/peer_name",
			&results->peer_name, sizeof(results->peer_name)))
		goto err;

	err = 0;
	goto out;
err:
	err = -1;
out:
	return err;
}

static int run_mod_test(const struct sock_addr_kern_test *test, int op,
			struct sock_addr_testmod_results *results)
{
	int err;

	if (!ASSERT_OK(load_mod(test, op), "load_mod"))
		goto err;

	if (!ASSERT_OK(read_mod_results(results), "read_mod_results"))
		goto err;

	err = 0;
	goto out;
err:
	err = -1;
out:
	if (!ASSERT_OK(unload_mod(), "unload_mod"))
		err = -1;

	return err;
}

static const char* ntop(int af, const struct sockaddr_storage *addr, char *buf,
			size_t buf_len)
{
	char ip_buf[256];
	struct sockaddr_in6 *sin6;
	struct sockaddr_in *sin;
	unsigned short port;

	switch (af) {
	case AF_INET:
		sin = (struct sockaddr_in *)addr;
		port = ntohs(sin->sin_port);

		if (!inet_ntop(AF_INET, &sin->sin_addr, ip_buf, sizeof(ip_buf)))
			goto err;

		break;
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)addr;
		port = ntohs(sin6->sin6_port);

		if (!inet_ntop(AF_INET6, &sin6->sin6_addr, ip_buf,
			       sizeof(ip_buf)))
			goto err;

		break;
	case AF_UNIX:
		strcpy(buf, ((struct sockaddr_un *)addr)->sun_path + 1);
		goto out;
	default:
		goto err;
	}

	sprintf(buf, "%s:%d", ip_buf, port);

	goto out;
err:
	buf = NULL;
out:
	return buf;
}

static void assert_addr_eq(const char *name, int af,
			   const struct sockaddr_storage *expected,
			   const struct sockaddr_storage *got, int cmp_port)
{
	int ret = cmp_addr(expected, 0, got, 0, cmp_port);
	char expected_buf[100];
	char got_buf[100];
	int duration = 0;

	CHECK(ret, name, "(expected=%s, got=%s)\n",
	      ntop(af, expected, expected_buf, sizeof(expected_buf)),
	      ntop(af, got, got_buf, sizeof(got_buf)));
}

static void test_kernel_bind(const struct sock_addr_kern_test *test)
{
	struct sock_addr_testmod_results results;
	struct sockaddr_storage requested_addr;
	struct sockaddr_storage expected_addr;
	socklen_t addr_len;
	int clientfd = -1;

	if (!ASSERT_OK(make_sockaddr(test->socket_family, test->requested_ip,
				     test->requested_port,
				     &requested_addr, NULL),
				     "make_requested_addr"))
		goto cleanup;

	if (!ASSERT_OK(make_sockaddr(test->socket_family, test->expected_ip,
				     test->expected_port,
				     &expected_addr, &addr_len),
				     "make_expected_addr"))
		goto cleanup;

	if (!ASSERT_OK(load_mod(test, BIND), "load_mod"))
		goto cleanup;

	/* Try to connect to server just in case */
	clientfd = connect_to_addr(&expected_addr, addr_len, test->socket_type);
	if (!ASSERT_GT(clientfd, 0, "connect_to_addr"))
		goto cleanup;

	if (!ASSERT_OK(read_mod_results(&results), "read_mod_results"))
		goto cleanup;

	if (!ASSERT_TRUE(results.success, "results_success"))
		goto cleanup;

	assert_addr_eq("addr", test->socket_family, &requested_addr,
		       &results.addr, 1);
	assert_addr_eq("sock_name", test->socket_family, &expected_addr,
		       &results.sock_name, 1);

cleanup:
	ASSERT_OK(unload_mod(), "unload_mod");
}

static void test_kernel_connect(const struct sock_addr_kern_test *test)
{
	struct sockaddr_storage expected_src_addr;
	struct sock_addr_testmod_results results;
	struct sockaddr_storage requested_addr;
	struct sockaddr_storage expected_addr;
	int servfd = -1;

	if (!ASSERT_OK(make_sockaddr(test->socket_family, test->requested_ip,
				     test->requested_port,
				     &requested_addr, NULL),
				     "make_requested_addr"))
		goto cleanup;

	if (!ASSERT_OK(make_sockaddr(test->socket_family, test->expected_ip,
				     test->expected_port,
				     &expected_addr, NULL),
				     "make_expected_addr"))
		goto cleanup;

	if (test->expected_src_ip)
		if (!ASSERT_OK(make_sockaddr(test->socket_family,
					     test->expected_src_ip, 0,
					     &expected_src_addr, NULL),
					     "make_expected_src_addr"))
		goto cleanup;

	/* Prepare server to connect to */
	servfd = start_server(test->socket_family, test->socket_type,
			    test->expected_ip, test->expected_port, 0);
	if (!ASSERT_GT(servfd, 0, "start_server"))
		goto cleanup;

	if (!ASSERT_OK(run_mod_test(test, CONNECT, &results), "run_mod_test"))
		goto cleanup;

	if (!ASSERT_TRUE(results.success, "results_success"))
		goto cleanup;

	assert_addr_eq("addr", test->socket_family, &requested_addr,
		       &results.addr, 1);
	if (test->expected_src_ip)
		assert_addr_eq("source_addr", test->socket_family, &expected_src_addr,
			&results.sock_name, 0);
	assert_addr_eq("peer_name", test->socket_family, &expected_addr,
	               &results.peer_name, 1);

cleanup:
	if (servfd > 0)
		close(servfd);
}

static void test_kernel_sendmsg(const struct sock_addr_kern_test *test)
{
	struct sock_addr_testmod_results results;
	struct sockaddr_storage expected_addr;
	struct sockaddr_storage sendmsg_addr;
	struct sockaddr_storage recvmsg_addr;
	int servfd = -1;

	if (!ASSERT_OK(make_sockaddr(test->socket_family, test->requested_ip,
				     test->requested_port,
				     &sendmsg_addr, NULL),
				     "make_requested_addr"))
		goto cleanup;

	if (test->expected_src_ip)
		if (!ASSERT_OK(make_sockaddr(test->socket_family, test->expected_src_ip,
					     0, &expected_addr, NULL),
					     "make_expected_src_addr"))
			goto cleanup;

	/* Prepare server to sendmsg to */
	servfd = start_server(test->socket_family, test->socket_type,
			      test->expected_ip, test->expected_port, 0);
	if (!ASSERT_GT(servfd, 0, "start_server"))
		goto cleanup;

	if (!ASSERT_OK(run_mod_test(test, SENDMSG, &results), "run_mod_test"))
		goto cleanup;

	if (!ASSERT_TRUE(results.success, "results_success"))
		goto cleanup;

	assert_addr_eq("msg_name", test->socket_family, &sendmsg_addr,
		       &results.addr, 1);

	if (!ASSERT_GT(recvmsg_from_client(servfd, &recvmsg_addr), 0,
		       "recvmsg_from_client"))
		goto cleanup;

	if (test->expected_src_ip)
		assert_addr_eq("source_addr", test->socket_family, &recvmsg_addr,
			       &expected_addr, 0);

cleanup:
	if (servfd > 0)
		close(servfd);
}

static void run_test_case(int cgfd, const struct sock_addr_kern_test *test)
{
	int progfd = -1;

	progfd = test->loadfn(test);
	if (!ASSERT_GE(progfd, 0, "loadfn"))
		goto cleanup;

	if (!ASSERT_OK(bpf_prog_attach(progfd, cgfd, test->attach_type,
			      BPF_F_ALLOW_OVERRIDE), "bpf_prog_attach"))
		goto cleanup;

	switch (test->attach_type) {
	case BPF_CGROUP_INET4_BIND:
	case BPF_CGROUP_INET6_BIND:
		test_kernel_bind(test);
		break;
	case BPF_CGROUP_INET4_CONNECT:
	case BPF_CGROUP_INET6_CONNECT:
	case BPF_CGROUP_UNIX_CONNECT:
		test_kernel_connect(test);
		break;
	case BPF_CGROUP_UDP4_SENDMSG:
	case BPF_CGROUP_UDP6_SENDMSG:
	case BPF_CGROUP_UNIX_SENDMSG:
		test_kernel_sendmsg(test);
		break;
	default:
		ASSERT_FAIL("attach_type not valid: %d", test->attach_type);
	}

cleanup:
	/* Detaching w/o checking return code: best effort attempt. */
	if (progfd != -1) {
		bpf_prog_detach(cgfd, test->attach_type);
		close(progfd);
	}
}

static void run_tests(int cgfd)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(tests); ++i) {
		if (!test__start_subtest(tests[i].descr))
			continue;

		run_test_case(cgfd, &tests[i]);
	}
}

static int setup_test_env(void)
{
	return system("./test_sock_addr.sh setup");
}

static int cleanup_test_env(void)
{
	return system("./test_sock_addr.sh cleanup");
}

void test_sock_addr_kern(void)
{
	int cgfd = -1;

	if (!ASSERT_OK(setup_cgroup_environment(), "setup_cgroup_environment"))
		goto cleanup;

	if (!ASSERT_OK(setup_test_env(), "setup_test_env"))
		goto cleanup;

	/* Attach programs to root cgroup so they interact with kernel socket
	 * operations.
	 */
	cgfd = get_root_cgroup();
	if (!ASSERT_GE(cgfd, 0, "get_root_cgroup"))
		goto cleanup;

	run_tests(cgfd);
cleanup:
	if (cgfd >= 0)
		close(cgfd);
	cleanup_cgroup_environment();
	cleanup_test_env();
}
