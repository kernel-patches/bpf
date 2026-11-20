// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2025. Huawei Technologies Co., Ltd */

/*
 * seccomp-install benchmark: measures the cost of installing seccomp filters
 *
 * Every producer spawns one worker thread per burst. The worker installs a batch of filters,
 * then exits. The throughput is collected from the completed worker batches.
 *
 * Options:
 *
 *   --sync-mode yes  Every worker waits until all workers of the burst are created, then all
 *                    of them start installing at the same time. This models many tasks
 *                    installing filters at once.
 *
 *   --sync-mode no   Each worker starts installing right away when it is created. This models
 *                    sequential installs.
 *
 *   --filter-len N   Number of instructions per filter, valid range is 4..4096, default is 128
 *
 *   --same-filter    Whether to install the same filter every time, yes or no, default yes. No
 *                    installs a unique filter every time.
 *
 *   --batch N        Install N filters per batch, default 8
 */
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <argp.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "bench.h"

/* per-task budget employed by kernel, a bigger batch fails the install */
#define SECCOMP_MAX_INSNS_PER_PATH	32768

static struct {
	struct counter hits;
	struct counter drops;
	pthread_barrier_t barrier;
	bool sync;
	bool distinct;
	unsigned int filter_len;
	unsigned int batch;
	/* unique filter id, its own cacheline, all workers bump it */
	unsigned int uniq __attribute__((aligned(128)));
} ctx;

static struct {
	unsigned int filter_len;
	unsigned int batch;
	unsigned int mode;
	unsigned int same_filter;
} args = {
	.filter_len = 128,
	.batch = 8,
	.mode = 1, /* sync */
	.same_filter = 1,
};

enum {
	ARG_SYNC_MODE = 12500,
	ARG_FILTER_LEN,
	ARG_BATCH,
	ARG_SAME_FILTER,
};

static const struct argp_option opts[] = {
	{ "sync-mode", ARG_SYNC_MODE, "SYNC_MODE", 0,
	  "Start every burst of workers at the same time: yes|no (default yes)" },
	{ "filter-len", ARG_FILTER_LEN, "FILTER_LEN", 0,
	  "Number of instructions per filter, within 4..4096 (default 128)" },
	{ "batch", ARG_BATCH, "BATCH", 0, "Filters installed per batch (default 8)" },
	{ "same-filter", ARG_SAME_FILTER, "SAME_FILTER", 0,
	  "Install the same filter every time or a unique one: yes|no (default yes)" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case ARG_SYNC_MODE:
		if (strcmp(arg, "yes") && strcmp(arg, "no")) {
			fprintf(stderr, "sync-mode must be yes or no\n");
			argp_usage(state);
		}
		args.mode = !strcmp(arg, "yes");
		break;
	case ARG_FILTER_LEN:
		args.filter_len = strtoul(arg, NULL, 10);
		if (args.filter_len < 4 || args.filter_len > BPF_MAXINSNS) {
			fprintf(stderr, "filter-len must be within 4..%d\n", BPF_MAXINSNS);
			argp_usage(state);
		}
		break;
	case ARG_BATCH:
		args.batch = strtoul(arg, NULL, 10);
		if (!args.batch) {
			fprintf(stderr, "batch must be positive\n");
			argp_usage(state);
		}
		break;
	case ARG_SAME_FILTER:
		if (strcmp(arg, "yes") && strcmp(arg, "no")) {
			fprintf(stderr, "same-filter must be yes or no\n");
			argp_usage(state);
		}
		args.same_filter = !strcmp(arg, "yes");
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
};

const struct argp bench_seccomp_install_argp = {
	.options = opts,
	.parser = parse_arg,
};

/*
 * Fill a filter of len instructions:
 *
 *	A += 0
 *	A += 1
 *	...
 *	A += len - 3
 *	A += uniq
 *	RET ALLOW
 *
 * The plain ALU body exercises the per instruction translation cost of the pipeline without any
 * filter logic. The k field of the second to last instruction carries the uniq value, a worker
 * installing unique filters patches it in place for every install, the rest of the image never
 * changes.
 */
static void fill_filter(struct sock_filter *insns, unsigned int len)
{
	int i;

	for (i = 0; i < len - 2; i++)
		insns[i] = (struct sock_filter)
			BPF_STMT(BPF_ALU | BPF_ADD | BPF_K, i);
	insns[i++] = (struct sock_filter)
		BPF_STMT(BPF_ALU | BPF_ADD | BPF_K, 0);
	insns[i++] = (struct sock_filter)
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
}

static void *install_batch(void *arg)
{
	struct sock_filter *insns = arg;
	struct sock_fprog prog = { .len = ctx.filter_len, .filter = insns };
	sigset_t mask;
	int i, err = 0;

	sigemptyset(&mask);
	sigaddset(&mask, SIGALRM);
	pthread_sigmask(SIG_BLOCK, &mask, NULL);

	if (ctx.sync)
		pthread_barrier_wait(&ctx.barrier);

	for (i = 0; i < ctx.batch; i++) {
		if (ctx.distinct)
			insns[ctx.filter_len - 2].k = __atomic_fetch_add(&ctx.uniq, 1, __ATOMIC_RELAXED);
		if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog)) {
			err = 1;
			break;
		}
	}

	return err ? (void *)1 : NULL;
}

static void *producer(void *input)
{
	struct sock_filter *insns;
	pthread_t thread;
	void *ret;

	insns = malloc(ctx.filter_len * sizeof(*insns));
	if (!insns) {
		atomic_inc(&ctx.drops.value);
		return NULL;
	}
	fill_filter(insns, ctx.filter_len);

	while (true) {
		if (pthread_create(&thread, NULL, install_batch, insns)) {
			atomic_inc(&ctx.drops.value);
			continue;
		}
		pthread_join(thread, &ret);
		if (ret)
			atomic_inc(&ctx.drops.value);
		else
			atomic_add(&ctx.hits.value, ctx.batch);
	}

	return NULL;
}

static void measure(struct bench_res *res)
{
	res->hits = atomic_swap(&ctx.hits.value, 0);
	res->drops = atomic_swap(&ctx.drops.value, 0);
}

/*
 * Installing a seccomp filter needs no_new_privs or CAP_SYS_ADMIN, set it here so the whole bench
 * runs unprivileged.
 */
static void setup(void)
{
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		fprintf(stderr, "PR_SET_NO_NEW_PRIVS failed: %d\n", -errno);
		exit(1);
	}

	if ((args.filter_len + 4) * args.batch > SECCOMP_MAX_INSNS_PER_PATH) {
		fprintf(stderr, "the batch exceeds the seccomp insns budget of one task\n");
		exit(1);
	}

	ctx.sync = args.mode;
	ctx.distinct = !args.same_filter;
	ctx.filter_len = args.filter_len;
	ctx.batch = args.batch;

	if (ctx.sync)
		pthread_barrier_init(&ctx.barrier, NULL, env.producer_cnt);
}

const struct bench bench_seccomp_install = {
	.name = "seccomp-install",
	.argp = &bench_seccomp_install_argp,
	.setup = setup,
	.producer_thread = producer,
	.measure = measure,
	.report_progress = hits_drops_report_progress,
	.report_final = hits_drops_report_final,
};
