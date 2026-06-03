// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <argp.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "sk_storage_bench.skel.h"
#include "bench.h"

static struct {
	struct sk_storage_bench *skel;
	int sock_fd;
	int cgroup_fd;
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

static void sk_storage_setup(void)
{
	struct sk_storage_bench *skel;
	int err;

	setup_libbpf();

	skel = sk_storage_bench__open_and_load();
	if (!skel) {
		fprintf(stderr, "Error opening/loading skeleton\n");
		exit(1);
	}
	ctx.skel = skel;

	ctx.cgroup_fd = open("/sys/fs/cgroup/unified", O_RDONLY);
	if (ctx.cgroup_fd < 0)
		ctx.cgroup_fd = open("/sys/fs/cgroup", O_RDONLY);
	if (ctx.cgroup_fd < 0) {
		fprintf(stderr, "Error opening cgroup\n");
		exit(1);
	}

	skel->links.bench_sk_storage_get =
		bpf_program__attach_cgroup(skel->progs.bench_sk_storage_get,
					   ctx.cgroup_fd);
	if (!skel->links.bench_sk_storage_get) {
		fprintf(stderr, "Error attaching program\n");
		exit(1);
	}

	ctx.sock_fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (ctx.sock_fd < 0) {
		fprintf(stderr, "Error creating socket\n");
		exit(1);
	}

	err = 0;
	socklen_t len = sizeof(err);

	getsockopt(ctx.sock_fd, 0xdead, 0xbeef, &err, &len);
}

static void sk_storage_measure(struct bench_res *res)
{
	res->hits = atomic_swap(&ctx.skel->bss->hits, 0);
}

static void *sk_storage_producer(void *input)
{
	int val;
	socklen_t len = sizeof(val);

	while (true)
		getsockopt(ctx.sock_fd, 0xdead, 0xbeef, &val, &len);

	return NULL;
}

const struct bench bench_sk_storage_get = {
	.name = "sk-storage-get",
	.validate = sk_storage_validate,
	.setup = sk_storage_setup,
	.producer_thread = sk_storage_producer,
	.measure = sk_storage_measure,
	.report_progress = ops_report_progress,
	.report_final = ops_report_final,
};
