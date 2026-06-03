// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <argp.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "sk_storage_bench.skel.h"
#include "bench.h"

/*
 * sk_storage_get benchmark.
 *
 * Creates nr_socks listening sockets (so they live in the TCP hashtable)
 * and drives a bpf_iter/tcp pass over them.  Each read() of the iterator
 * visits every socket once, calling bpf_sk_storage_get() on a different
 * (cold) socket each time.  The syscall cost is amortized over all
 * sockets, so the measured rate reflects the storage-access cost rather
 * than getsockopt() overhead.  With a large socket count the working set
 * exceeds the CPU caches, which is where reserved inline storage avoids
 * the pointer chase of the hash-based path.
 */

static struct {
	__u32 nr_socks;
} args = {
	.nr_socks = 100000,
};

enum {
	ARG_NR_SOCKS = 8000,
};

static const struct argp_option opts[] = {
	{ "nr-socks", ARG_NR_SOCKS, "NR_SOCKS", 0,
	  "Number of listening sockets to iterate (default 100000)" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long ret;

	switch (key) {
	case ARG_NR_SOCKS:
		ret = strtol(arg, NULL, 10);
		if (ret < 1 || ret > INT_MAX) {
			fprintf(stderr, "invalid nr-socks\n");
			argp_usage(state);
		}
		args.nr_socks = ret;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

const struct argp bench_sk_storage_argp = {
	.options = opts,
	.parser = parse_arg,
};

static struct {
	struct sk_storage_bench *skel;
	struct bpf_link *link;
	int *sock_fds;
	__u32 nr_socks;
} ctx;

static void sk_storage_validate(void)
{
	if (env.producer_cnt != 1) {
		fprintf(stderr, "benchmark needs single producer\n");
		exit(1);
	}
	if (env.consumer_cnt != 0) {
		fprintf(stderr, "benchmark does not support consumers\n");
		exit(1);
	}
}

/* One bpf_iter/tcp pass over all sockets in the netns. */
static void iter_pass(void)
{
	char buf[64];
	int iter_fd;
	ssize_t n;

	iter_fd = bpf_iter_create(bpf_link__fd(ctx.link));
	if (iter_fd < 0) {
		fprintf(stderr, "Error creating iter fd\n");
		exit(1);
	}

	while ((n = read(iter_fd, buf, sizeof(buf))) > 0)
		;

	close(iter_fd);
}

static void sk_storage_setup(void)
{
	struct rlimit rlim;
	int i;

	setup_libbpf();

	rlim.rlim_cur = rlim.rlim_max = args.nr_socks + 1024;
	if (setrlimit(RLIMIT_NOFILE, &rlim)) {
		fprintf(stderr, "Error raising RLIMIT_NOFILE for %u sockets\n",
			args.nr_socks);
		exit(1);
	}

	ctx.skel = sk_storage_bench__open_and_load();
	if (!ctx.skel) {
		fprintf(stderr, "Error opening/loading skeleton\n");
		exit(1);
	}

	ctx.nr_socks = args.nr_socks;
	ctx.sock_fds = calloc(ctx.nr_socks, sizeof(*ctx.sock_fds));
	if (!ctx.sock_fds) {
		fprintf(stderr, "Error allocating socket array\n");
		exit(1);
	}

	/*
	 * Create listening sockets so each lives in the TCP listen
	 * hashtable and is visited by iter/tcp.  Spread (addr, port)
	 * across 127.0.0.0/8 to avoid ephemeral port exhaustion.
	 */
	for (i = 0; i < ctx.nr_socks; i++) {
		struct sockaddr_in addr = {
			.sin_family = AF_INET,
			.sin_port = htons(1024 + (i % 60000)),
		};
		int fd;

		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK + i / 60000);

		fd = socket(AF_INET, SOCK_STREAM, 0);
		if (fd < 0) {
			fprintf(stderr, "Error creating socket %d\n", i);
			exit(1);
		}
		if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) ||
		    listen(fd, 1)) {
			fprintf(stderr, "Error binding/listening socket %d\n", i);
			exit(1);
		}
		ctx.sock_fds[i] = fd;
	}

	ctx.link = bpf_program__attach_iter(ctx.skel->progs.iter_sk_storage_get,
					    NULL);
	if (!ctx.link) {
		fprintf(stderr, "Error attaching iter program\n");
		exit(1);
	}

	/* Warm up: create storage so the measured loop is get-existing. */
	iter_pass();
}

static void sk_storage_measure(struct bench_res *res)
{
	res->hits = atomic_swap(&ctx.skel->bss->hits, 0);
}

static void *sk_storage_producer(void *input)
{
	while (true)
		iter_pass();

	return NULL;
}

const struct bench bench_sk_storage_get = {
	.name = "sk-storage-get",
	.argp = &bench_sk_storage_argp,
	.validate = sk_storage_validate,
	.setup = sk_storage_setup,
	.producer_thread = sk_storage_producer,
	.measure = sk_storage_measure,
	.report_progress = ops_report_progress,
	.report_final = ops_report_final,
};
