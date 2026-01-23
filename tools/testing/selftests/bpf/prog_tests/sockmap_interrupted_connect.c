// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <error.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <linux/string.h>
#include <linux/time64.h>
#include <linux/vm_sockets.h>

#include "linux/const.h"
#include "test_progs.h"
#include "sockmap_helpers.h"

#define STR(s)	#s
#define XSTR(s)	STR(s)

#define TIMEOUT	5	/* seconds */
#define INVALID	0x4242

struct socket_spec {
	int domain;
	int sotype;
};

struct context {
	struct sockaddr_storage addr, bad;
	struct socket_spec *ss;
	char str[MAX_TEST_NAME];
	socklen_t alen;
	int s, c, map;
};

static void handler(int signum)
{
	/* nop */
}

static void *racer(void *arg)
{
	struct context *ctx = arg;
	int *map = &ctx->map;
	pid_t pid = getpid();

	for (;;) {
		if (kill(pid, SIGUSR1)) {
			FAIL_ERRNO("kill");
			break;
		}

		(void)bpf_map_update_elem(*map, &u32(0), &ctx->c, BPF_ANY);
		pthread_testcancel();
	}

	return NULL;
}

static void test_reconnect(struct context *ctx)
{
	struct socket_spec *ss = ctx->ss;
	__u64 tout;

	tout = get_time_ns() + TIMEOUT * NSEC_PER_SEC;
	do {
		int c;

		c = xsocket(ss->domain, ss->sotype, 0);
		if (c < 0)
			break;
		ctx->c = c;

		if ((ss->sotype & SOCK_TYPE_MASK) == SOCK_DGRAM) {
			struct sockaddr_storage ca;
			socklen_t len;

			init_addr_loopback(ss->domain, &ca, &len);
			if (xbind(c, sockaddr(&ca), len)) {
				xclose(c);
				break;
			}
		}

		(void)connect(c, (struct sockaddr *)&ctx->addr, ctx->alen);
		(void)connect(c, (struct sockaddr *)&ctx->bad, ctx->alen);
		(void)recv(c, &(char){}, 1, MSG_DONTWAIT);

		for (;;) {
			int p = accept(ctx->s, NULL, NULL);

			if (p < 0)
				break;
			xclose(p);
		}

		xclose(c);
	} while (get_time_ns() < tout);
}

#define __TEST_RECONNECT_ADDR(addr_struct, mangle, mangle_s)			\
	({									\
		char str[MAX_TEST_NAME * 2];					\
										\
		memcpy(&ctx->bad, &ctx->addr, ctx->alen);			\
		((struct addr_struct *)&ctx->bad)->mangle;			\
										\
		snprintf(str, sizeof(str), "%s %-24.24s ", ctx->str, mangle_s);	\
		if (test__start_subtest(str))					\
			test_reconnect(ctx);					\
	})

#define TEST_RECONNECT_ADDR(addr_struct, mangle)				\
	__TEST_RECONNECT_ADDR(addr_struct, mangle, XSTR(mangle))

static void test_socket(struct context *ctx)
{
	struct socket_spec *ss = ctx->ss;
	socklen_t alen;
	int s;

	s = socket_loopback(ss->domain, ss->sotype | SOCK_NONBLOCK);
	if (s < 0)
		return;

	alen = sizeof(ctx->addr);
	if (xgetsockname(s, sockaddr(&ctx->addr), &alen))
		goto cleanup;

	ctx->s = s;
	ctx->alen = alen;
	sprintf(ctx->str + strlen(ctx->str), "%-5s ", socket_kind_to_str(s));

	switch (ss->domain) {
	case AF_UNIX:
		TEST_RECONNECT_ADDR(sockaddr_un, sun_family = AF_UNSPEC);
		TEST_RECONNECT_ADDR(sockaddr_un, sun_path[0] = (char)INVALID);
		break;
	case AF_VSOCK:
		TEST_RECONNECT_ADDR(sockaddr_vm, svm_cid = INVALID);
		break;
	default:
		FAIL("Unknown socket domain %#x", ss->domain);
	}

cleanup:
	xclose(s);
}

static void test_map(struct context *ctx, enum bpf_map_type type)
{
	/* Filter by any `struct proto` that defines psock_update_sk_prot() */
	struct socket_spec *ss, sockets[] = {
		{ AF_UNIX, SOCK_STREAM },
		{ AF_UNIX, SOCK_DGRAM },
		// { AF_UNIX, SOCK_SEQPACKET },	/* see unix_dgram_bpf_update_proto() */
		{ AF_VSOCK, SOCK_STREAM },
		// { AF_VSOCK, SOCK_DGRAM },	/* see vsock_bpf_update_proto() */
		{ AF_VSOCK, SOCK_SEQPACKET },
	};

	ctx->map = bpf_map_create(type, NULL, sizeof(int), sizeof(int), 1, NULL);
	if (!ASSERT_OK_FD(ctx->map, "map"))
		return;

	for (ss = sockets; ss < sockets + ARRAY_SIZE(sockets); ss++) {
		sprintf(ctx->str, "%-3s ",
			type == BPF_MAP_TYPE_SOCKMAP ? "map" : "?");
		ctx->ss = ss;

		test_socket(ctx);
	}

	xclose(ctx->map);
}

void serial_test_sockmap_interrupted_connect(void)
{
	sighandler_t orig_handler;
	struct context ctx = {0};
	pthread_t tid;

	orig_handler = signal(SIGUSR1, handler);
	if (!ASSERT_NEQ(orig_handler, SIG_ERR, "signal"))
		return;

	if (xpthread_create(&tid, NULL, racer, &ctx))
		goto restore;

	test_map(&ctx, BPF_MAP_TYPE_SOCKMAP);

	if (!xpthread_cancel(tid))
		xpthread_join(tid, NULL);
restore:
	ASSERT_NEQ(signal(SIGUSR1, orig_handler), SIG_ERR, "handler restore");
}
