// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Isovalent */

#include <arpa/inet.h>

#include "test_progs.h"
#include "network_helpers.h"
#include "ksock_basic.skel.h"
#include "ksock_recursion.skel.h"

#define NS_TEST "ksock_basic_ns"
#define NS_LSM_RECURSION_TEST "ksock_lsm_recursion_ns"
#define LOOPBACK_IP "127.0.0.1"
#define RECV_PORT 7777
#define RECV_TIMEOUT_SEC 5

struct ksock_test_env {
	const char *netns;
	bool netns_created;
	struct nstoken *nstoken;
	struct sockaddr_in addr;
	int rfd;
	char buf[32];
};

static bool ksock_test_env_setup(struct ksock_test_env *env, const char *netns)
{
	struct timeval tv;
	int err;

	memset(env, 0, sizeof(*env));
	env->netns = netns;
	env->rfd = -1;

	SYS(fail, "ip netns add %s", netns);
	env->netns_created = true;
	SYS(fail, "ip -net %s link set lo up", netns);

	env->nstoken = open_netns(netns);
	if (!ASSERT_OK_PTR(env->nstoken, "open_netns"))
		goto fail;

	env->rfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (!ASSERT_OK_FD(env->rfd, "receiver socket"))
		goto fail;

	env->addr.sin_family = AF_INET;
	env->addr.sin_addr.s_addr = inet_addr(LOOPBACK_IP);
	env->addr.sin_port = htons(RECV_PORT);

	err = bind(env->rfd, (struct sockaddr *)&env->addr, sizeof(env->addr));
	if (!ASSERT_OK(err, "bind receiver"))
		goto fail;

	tv.tv_sec = RECV_TIMEOUT_SEC;
	tv.tv_usec = 0;
	err = setsockopt(env->rfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	if (!ASSERT_OK(err, "set rcvtimeo"))
		goto fail;

	return true;

fail:
	if (env->rfd >= 0) {
		close(env->rfd);
		env->rfd = -1;
	}
	if (env->nstoken) {
		close_netns(env->nstoken);
		env->nstoken = NULL;
	}
	if (env->netns_created) {
		SYS_NOFAIL("ip netns del %s >/dev/null 2>&1", netns);
		env->netns_created = false;
	}
	return false;
}

static void ksock_test_env_cleanup(struct ksock_test_env *env)
{
	if (env->rfd >= 0)
		close(env->rfd);
	if (env->nstoken)
		close_netns(env->nstoken);
	if (env->netns_created) {
		SYS_NOFAIL("ip netns del %s >/dev/null 2>&1", env->netns);
		env->netns_created = false;
	}
}

static void ksock_assert_recv(struct ksock_test_env *env, const char *data,
			      size_t data_sz)
{
	ssize_t n;

	memset(env->buf, 0, sizeof(env->buf));
	n = recvfrom(env->rfd, env->buf, sizeof(env->buf), 0, NULL, NULL);
	if (!ASSERT_EQ(n, data_sz, "recvfrom len"))
		return;
	ASSERT_MEMEQ(env->buf, data, data_sz, "payload match");
}

static bool ksock_setup_ctx(struct bpf_program *prog, __be32 *ipv4_remote,
			    __u16 *remote_port)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err, pfd;

	*ipv4_remote = inet_addr(LOOPBACK_IP);
	*remote_port = RECV_PORT;

	pfd = bpf_program__fd(prog);
	if (!ASSERT_OK_FD(pfd, "ksock_setup fd"))
		return false;

	err = bpf_prog_test_run_opts(pfd, &opts);
	if (!ASSERT_OK(err, "ksock_setup run"))
		return false;
	if (!ASSERT_OK(opts.retval, "ksock_setup retval"))
		return false;

	return true;
}

void test_ksock_basic(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct ksock_test_env env;
	struct ksock_basic *skel;
	int err, pfd;

	skel = ksock_basic__open();
	if (!ASSERT_OK_PTR(skel, "skel open"))
		return;

	err = ksock_basic__load(skel);
	if (!ASSERT_OK(err, "skel load")) {
		ksock_basic__destroy(skel);
		return;
	}

	if (!ksock_test_env_setup(&env, NS_TEST))
		goto fail;

	/* Step 1: Run the setup SYSCALL prog to create ksock */
	if (!ksock_setup_ctx(skel->progs.ksock_setup,
			     &skel->bss->ipv4_remote,
			     &skel->bss->remote_port))
		goto fail;

	/* Step 2: Run the send SYSCALL prog */
	pfd = bpf_program__fd(skel->progs.ksock_send);
	if (!ASSERT_OK_FD(pfd, "ksock_send fd"))
		goto fail;

	err = bpf_prog_test_run_opts(pfd, &opts);
	if (!ASSERT_OK(err, "ksock_send run"))
		goto fail;
	if (!ASSERT_EQ(opts.retval,
		       sizeof(skel->data->send_data), "sendmsg bytes"))
		goto fail;

	/* Step 3: Receive and verify the data */
	ksock_assert_recv(&env, skel->data->send_data,
			  sizeof(skel->data->send_data));

fail:
	ksock_test_env_cleanup(&env);
	ksock_basic__destroy(skel);
}

void test_ksock_lsm_recursion(void)
{
	struct ksock_test_env env;
	struct ksock_recursion *skel;
	char trigger = 'x';
	int tfd = -1;
	int err;
	ssize_t n;

	skel = ksock_recursion__open();
	if (!ASSERT_OK_PTR(skel, "skel open"))
		return;

	err = ksock_recursion__load(skel);
	if (!ASSERT_OK(err, "skel load")) {
		ksock_recursion__destroy(skel);
		return;
	}

	if (!ksock_test_env_setup(&env, NS_LSM_RECURSION_TEST))
		goto fail;

	/* Step 1: Run the setup SYSCALL prog to create the ksock */
	if (!ksock_setup_ctx(skel->progs.ksock_setup,
			     &skel->bss->ipv4_remote,
			     &skel->bss->remote_port))
		goto fail;

	/* Step 2: Attach LSM prog and trigger socket_sendmsg from userspace */
	skel->links.ksock_socket_sendmsg =
		bpf_program__attach_lsm(skel->progs.ksock_socket_sendmsg);
	if (!ASSERT_OK_PTR(skel->links.ksock_socket_sendmsg,
			   "attach socket_sendmsg lsm"))
		goto fail;

	tfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (!ASSERT_OK_FD(tfd, "trigger socket"))
		goto fail;

	skel->bss->target_pid = getpid();
	skel->bss->trigger_send = 1;
	n = sendto(tfd, &trigger, sizeof(trigger), 0,
		   (struct sockaddr *)&env.addr, sizeof(env.addr));
	skel->bss->target_pid = 0;
	skel->bss->trigger_send = 0;
	if (!ASSERT_EQ(n, sizeof(trigger), "trigger sendto"))
		goto fail;

	/* Step 3: The nested bpf_ksock_send() must hit the recursion guard */
	if (!ASSERT_EQ(skel->bss->rec_count, 2,
		       "socket_sendmsg recursion count"))
		goto fail;
	if (!ASSERT_EQ(skel->data->rec_kfunc_rets[0], -EBUSY,
		       "recursive send status"))
		goto fail;
	if (!ASSERT_EQ(skel->data->rec_kfunc_rets[1],
		       sizeof(skel->data->send_data), "outer send bytes"))
		goto fail;

	ksock_assert_recv(&env, skel->data->send_data,
			  sizeof(skel->data->send_data));

fail:
	if (tfd >= 0)
		close(tfd);
	ksock_test_env_cleanup(&env);
	ksock_recursion__destroy(skel);
}
