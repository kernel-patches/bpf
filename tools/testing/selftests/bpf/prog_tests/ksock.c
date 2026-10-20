// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Isovalent */

#include <arpa/inet.h>

#include "test_progs.h"
#include "network_helpers.h"
#include "ksock_lsm.skel.h"
#include "ksock_lsm_verifier.skel.h"

#define NS_TEST "ksock_lsm_ns"
#define RECV_PORT 7777
#define RECV_TIMEOUT_SEC 5

struct ksock_test_env {
	struct nstoken *nstoken;
	int rfd;
};

struct ksock_test_case {
	const char *name;
	bool connect_in_syscall;
	bool connect_in_lsm;
};

static bool ksock_test_env_setup(struct ksock_test_env *env)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = htons(RECV_PORT),
	};
	struct timeval tv = { .tv_sec = RECV_TIMEOUT_SEC };
	int err;

	memset(env, 0, sizeof(*env));
	env->rfd = -1;

	if (!ASSERT_OK(make_netns(NS_TEST), "make_netns"))
		goto fail;

	env->nstoken = open_netns(NS_TEST);
	if (!ASSERT_OK_PTR(env->nstoken, "open_netns"))
		goto fail;

	env->rfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (!ASSERT_OK_FD(env->rfd, "receiver socket"))
		goto fail;

	err = bind(env->rfd, (struct sockaddr *)&addr, sizeof(addr));
	if (!ASSERT_OK(err, "bind receiver"))
		goto fail;

	err = setsockopt(env->rfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	if (!ASSERT_OK(err, "set rcvtimeo"))
		goto fail;

	return true;

fail:
	return false;
}

static void test_ksock_lsm_case(const struct ksock_test_case *test)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct sockaddr_in trigger_addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	struct ksock_test_env env;
	struct ksock_lsm *skel;
	char recv_data[sizeof(skel->data->send_data)] = {};
	bool connected = test->connect_in_syscall || test->connect_in_lsm;
	int expected_send_ret = connected ? (int)sizeof(skel->data->send_data) : -EDESTADDRREQ;
	ssize_t n;
	int tfd = -1;
	int err;

	skel = ksock_lsm__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel open_and_load"))
		return;

	if (!ksock_test_env_setup(&env))
		goto fail;

	/* Step 1: Run the setup SYSCALL prog to create the ksock */
	skel->bss->ipv4_remote = htonl(INADDR_LOOPBACK);
	skel->bss->remote_port = RECV_PORT;
	skel->bss->connect_in_syscall = test->connect_in_syscall;
	skel->bss->connect_in_lsm = test->connect_in_lsm;
	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.ksock_setup),
				     &opts);
	if (!ASSERT_OK(err, "ksock_setup run"))
		goto fail;
	if (!ASSERT_OK(opts.retval, "ksock_setup retval"))
		goto fail;

	/* Step 2: Attach LSM prog and trigger socket_bind from userspace */
	skel->links.ksock_socket_bind =
		bpf_program__attach_lsm(skel->progs.ksock_socket_bind);
	if (!ASSERT_OK_PTR(skel->links.ksock_socket_bind,
			   "attach socket_bind lsm"))
		goto fail;

	tfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (!ASSERT_OK_FD(tfd, "trigger socket"))
		goto fail;

	skel->bss->target_pid = getpid();
	err = bind(tfd, (struct sockaddr *)&trigger_addr, sizeof(trigger_addr));
	skel->bss->target_pid = 0;
	if (!ASSERT_OK(err, "trigger bind"))
		goto fail;

	/* Step 3: Verify the operations and received notification, if any. */
	if (!ASSERT_EQ(skel->data->connect_ret, connected ? 0 : -1, "connect retval"))
		goto fail;

	if (!ASSERT_EQ(skel->data->send_ret, expected_send_ret, "LSM send retval"))
		goto fail;

	n = recvfrom(env.rfd, recv_data, sizeof(recv_data),
		     connected ? 0 : MSG_DONTWAIT, NULL, NULL);
	if (!connected) {
		if (ASSERT_EQ(n, -1, "no datagram"))
			ASSERT_EQ(errno, EAGAIN, "recvfrom errno");
		goto fail;
	}

	if (!ASSERT_EQ(n, sizeof(recv_data), "recvfrom len") ||
	    !ASSERT_MEMEQ(recv_data, skel->data->send_data, sizeof(recv_data),
			  "payload match"))
		goto fail;

fail:
	if (tfd >= 0)
		close(tfd);
	if (env.rfd >= 0)
		close(env.rfd);
	if (env.nstoken)
		close_netns(env.nstoken);
	remove_netns(NS_TEST);
	ksock_lsm__destroy(skel);
}

void test_ksock_lsm(void)
{
	static const struct ksock_test_case tests[] = {
		{ .name = "unconnected_send" },
		{ .name = "syscall_connect_send", .connect_in_syscall = true },
		{ .name = "lsm_connect_send", .connect_in_lsm = true },
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		if (test__start_subtest(tests[i].name))
			test_ksock_lsm_case(&tests[i]);
	}
}

void test_ksock_lsm_verifier(void)
{
	RUN_TESTS(ksock_lsm_verifier);
}
