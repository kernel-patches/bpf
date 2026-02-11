// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <math.h>
#include <time.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "conctest.skel.h"

#define MAX_FILTERS 64
#define MAX_ATTACH_LINKS 1024
#define NMI_SAMPLE_PERIOD 1000
#define DEFAULT_DURATION 5
#define DEFAULT_NR_CPUS 1

#define CONCTEST_HIST_BUCKETS 28
#define EDEADLK 35
#define ETIMEDOUT 110
#define HIST_BAR_WIDTH 40

static int nmi_sample_period = NMI_SAMPLE_PERIOD;
static volatile int stop;
static int verbose;
static __u32 delay_seed;
static __u32 delay_max_us = 10;
static __u32 delay_us;

enum conctest_stat_id {
	CONCTEST_STAT_SYSCALL = 0,
	CONCTEST_STAT_NMI,
	CONCTEST_STAT_MAX,
};

static const char *stat_names[CONCTEST_STAT_MAX] = {
	[CONCTEST_STAT_SYSCALL] = "syscall",
	[CONCTEST_STAT_NMI] = "nmi",
};

struct conctest_op_stats {
	__u64 count;
	__u64 success;
	__u64 failure;
	__u64 unexpected;
	__u64 total_ns;
	__u64 min_ns;
	__u64 max_ns;
	__u64 hist[CONCTEST_HIST_BUCKETS];
};

struct conctest_op_state {
	__s64 expect_ret;
	__u64 delay_thresh_ns;
	__u64 failed_print_once;
	__u64 delay_print_once;
};

/* Upper boundary (exclusive) of each histogram bucket, in ns */
static const __u64 hist_upper[CONCTEST_HIST_BUCKETS] = {
	1000, /* [0, 1us) */
	100000, /* [1us, 100us) */
	200000,	    300000,	400000,	   500000,    600000,
	700000,	    800000,	900000,	   1000000, /* [900us, 1ms) */
	10000000, /* [1ms, 10ms) */
	20000000,   30000000,	40000000,  50000000,  60000000,
	70000000,   80000000,	90000000,  100000000, /* [90ms, 100ms) */
	150000000,  200000000,	250000000, 500000000, 750000000,
	1000000000, UINT64_MAX, /* [1s, inf) */
};

static void format_ns(char *buf, size_t sz, __u64 ns)
{
	if (ns < 1000)
		snprintf(buf, sz, "%lluns", (unsigned long long)ns);
	else if (ns < 1000000)
		snprintf(buf, sz, "%.1fus", ns / 1000.0);
	else if (ns < 1000000000)
		snprintf(buf, sz, "%.1fms", ns / 1000000.0);
	else
		snprintf(buf, sz, "%.2fs", ns / 1000000000.0);
}

static void format_bucket_range(char *buf, size_t sz, int i)
{
	__u64 lo = i > 0 ? hist_upper[i - 1] : 0;
	__u64 hi = hist_upper[i];
	char lo_s[32], hi_s[32];

	format_ns(lo_s, sizeof(lo_s), lo);
	if (hi == UINT64_MAX)
		snprintf(buf, sz, "[%7s, inf)", lo_s);
	else {
		format_ns(hi_s, sizeof(hi_s), hi);
		snprintf(buf, sz, "[%7s, %7s)", lo_s, hi_s);
	}
}

static __u64 estimate_median(struct conctest_op_stats *s)
{
	__u64 half = s->count / 2;
	__u64 cumulative = 0;
	int i;

	for (i = 0; i < CONCTEST_HIST_BUCKETS; i++) {
		cumulative += s->hist[i];
		if (cumulative >= half) {
			__u64 lo = i > 0 ? hist_upper[i - 1] : 0;
			__u64 hi = hist_upper[i];

			if (hi == UINT64_MAX)
				return lo;
			return (lo + hi) / 2;
		}
	}
	return 0;
}

static __u64 estimate_stddev(struct conctest_op_stats *s)
{
	double mean, sum_sq = 0;
	int i;

	if (s->count < 2)
		return 0;

	mean = (double)s->total_ns / s->count;

	for (i = 0; i < CONCTEST_HIST_BUCKETS; i++) {
		double lo, hi, mid, diff;

		if (!s->hist[i])
			continue;

		lo = i > 0 ? (double)hist_upper[i - 1] : 0;
		hi = hist_upper[i] == UINT64_MAX ? lo : (double)hist_upper[i];
		mid = (lo + hi) / 2;
		diff = mid - mean;
		sum_sq += s->hist[i] * diff * diff;
	}

	return (__u64)sqrt(sum_sq / s->count);
}

static void print_histogram(struct conctest_op_stats *s)
{
	int i, j, len, last_printed = -1;
	__u64 max_count = 0;

	for (i = 0; i < CONCTEST_HIST_BUCKETS; i++)
		if (s->hist[i] > max_count)
			max_count = s->hist[i];

	if (!max_count)
		return;

	printf("  Histogram:\n");
	for (i = 0; i < CONCTEST_HIST_BUCKETS; i++) {
		char range[48];

		if (!s->hist[i])
			continue;

		if (last_printed >= 0 && i > last_printed + 1)
			printf("           ...\n");
		last_printed = i;

		format_bucket_range(range, sizeof(range), i);
		printf("    %s %8llu |", range, (unsigned long long)s->hist[i]);

		len = max_count ? (int)(s->hist[i] * HIST_BAR_WIDTH / max_count) : 0;
		for (j = 0; j < len; j++)
			putchar('#');
		printf("\n");
	}
}

static int dump_test_stats(struct conctest *skel)
{
	char avg_str[32], min_str[32], max_str[32], med_str[32], stddev_str[32], thresh_str[32];
	int ncpus = libbpf_num_possible_cpus();
	struct conctest_op_stats *per_cpu;
	struct conctest_op_state state;
	struct conctest_op_stats agg;
	int has_error = 0;
	int id, cpu, b;

	per_cpu = calloc(ncpus, sizeof(*per_cpu));
	if (!per_cpu)
		return -ENOMEM;

	for (id = 0; id < CONCTEST_STAT_MAX; id++) {
		int has_min = 0;
		int key = id;

		if (bpf_map__lookup_elem(skel->maps.perf_map, &key, sizeof(key),
					 per_cpu, ncpus * sizeof(*per_cpu), 0))
			continue;

		memset(&agg, 0, sizeof(agg));
		for (cpu = 0; cpu < ncpus; cpu++) {
			struct conctest_op_stats *p = &per_cpu[cpu];

			agg.count += p->count;
			agg.success += p->success;
			agg.failure += p->failure;
			agg.unexpected += p->unexpected;
			agg.total_ns += p->total_ns;

			if (p->count > 0) {
				if (!has_min || p->min_ns < agg.min_ns) {
					agg.min_ns = p->min_ns;
					has_min = 1;
				}
			}
			if (p->max_ns > agg.max_ns)
				agg.max_ns = p->max_ns;

			for (b = 0; b < CONCTEST_HIST_BUCKETS; b++)
				agg.hist[b] += p->hist[b];
		}

		if (!agg.count)
			continue;

		if (bpf_map__lookup_elem(skel->maps.state_map, &key,
					 sizeof(key), &state, sizeof(state), 0))
			memset(&state, 0, sizeof(state));

		format_ns(avg_str, sizeof(avg_str), agg.total_ns / agg.count);
		format_ns(min_str, sizeof(min_str), agg.min_ns);
		format_ns(max_str, sizeof(max_str), agg.max_ns);
		format_ns(med_str, sizeof(med_str), estimate_median(&agg));
		format_ns(stddev_str, sizeof(stddev_str), estimate_stddev(&agg));

		if (agg.unexpected || state.delay_print_once)
			has_error = 1;

		if (!verbose && !has_error)
			continue;
		printf("=== Stats: %s ===\n",
		       stat_names[id] ? stat_names[id] : "unknown");
		printf("  Count: %lu (success: %lu, failure: %lu, unexpected: %lu)\n",
		       (unsigned long)agg.count,
		       (unsigned long)agg.success,
		       (unsigned long)agg.failure,
		       (unsigned long)agg.unexpected);
		printf("  Timing: avg=%s min=%s max=%s median=~%s stddev=~%s\n",
		       avg_str, min_str, max_str, med_str, stddev_str);
		if (state.delay_thresh_ns) {
			format_ns(thresh_str, sizeof(thresh_str), state.delay_thresh_ns);
			printf("  Delay threshold: %s (exceeded: %s)\n", thresh_str,
			       state.delay_print_once ? "YES" : "no");
		}
		print_histogram(&agg);
	}

	free(per_cpu);
	return has_error ? -1 : 0;
}

enum conctest_cfg_type {
	CT_INVALID = 0,
	CT_TASK_PROG,
	CT_NMI_PROG,
	CT_ATTACH_PROG,
};

struct conctest_cfg {
	enum conctest_cfg_type type;
	union {
		struct {
			const char *prog_name;
		} task;
		struct {
			const char *prog_name;
		} nmi;
		struct {
			struct bpf_program *(*get_prog)(struct conctest *skel,
							struct conctest_cfg *cfg,
							bool loaded);
			const char *tp_category;
			const char *tp_name;
		} attach;
	};
};

#define for_each_conctest_cfg(cfg, arr) \
	for (struct conctest_cfg *cfg = (arr); cfg->type != CT_INVALID; cfg++)

struct conctest_test {
	const char *name;
	struct conctest_cfg *cfgs;
	void (*init)(struct conctest *skel);
	int nr_cpus;
};

struct conctest_cfg rqspinlock[] = {
	{
		.type = CT_TASK_PROG,
		.task = { "conctest_rqspinlock_task" },
	},
	{
		.type = CT_NMI_PROG,
		.nmi = { "conctest_rqspinlock_nmi" },
	},
	{}
};

struct conctest_cfg rqspinlock_shift[] = {
	{
		.type = CT_TASK_PROG,
		.task = { "conctest_rqspinlock_task" },
	},
	{
		.type = CT_NMI_PROG,
		.nmi = { "conctest_rqspinlock_nmi_shift" },
	},
	{}
};

static void __rqspinlock_init(struct conctest *skel, int err, int delay)
{
	struct conctest_op_state state;
	int key;

	key = CONCTEST_STAT_SYSCALL;
	memset(&state, 0, sizeof(state));
	state.expect_ret = 0;
	state.delay_thresh_ns = 1000000 * delay;
	bpf_map__update_elem(skel->maps.state_map, &key, sizeof(key), &state,
			     sizeof(state), 0);

	key = CONCTEST_STAT_NMI;
	memset(&state, 0, sizeof(state));
	state.expect_ret = err;
	state.delay_thresh_ns = 1000000 * delay;
	bpf_map__update_elem(skel->maps.state_map, &key, sizeof(key), &state,
			     sizeof(state), 0);
}

static void rqspinlock_init(struct conctest *skel)
{
	return __rqspinlock_init(skel, -EDEADLK, 2);
}

static void rqspinlock_init_delay(struct conctest *skel)
{
	return __rqspinlock_init(skel, -EDEADLK, 10);
}

static void rqspinlock_init_timeout(struct conctest *skel)
{
	return __rqspinlock_init(skel, -ETIMEDOUT, 300);
}

static struct conctest_test all_tests[] = {
	{
		.name = "rqspinlock:AA",
		.cfgs = rqspinlock,
		.init = rqspinlock_init,
		.nr_cpus = 1
	},
	{
		.name = "rqspinlock:ABBA",
		.cfgs = rqspinlock_shift,
		.init = rqspinlock_init_delay,
		.nr_cpus = 2
	},
	{
		.name = "rqspinlock:ABBCBA",
		.cfgs = rqspinlock_shift,
		.init = rqspinlock_init_timeout,
		.nr_cpus = 3
	},
	{},
};

struct task_ctx {
	int prog_fd;
	int cpu;
};

static int pin_to_cpu(int cpu)
{
	cpu_set_t cpuset;

	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);
	return pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
}

static void *worker(void *arg)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts, .repeat = 1000);
	struct task_ctx *ctx = arg;

	if (pin_to_cpu(ctx->cpu)) {
		fprintf(stderr, "Failed to pin to CPU %d\n", ctx->cpu);
		return NULL;
	}

	while (!stop)
		bpf_prog_test_run_opts(ctx->prog_fd, &opts);

	return NULL;
}

static int open_perf_event(int cpu)
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_HARDWARE,
		.config = PERF_COUNT_HW_CPU_CYCLES,
		.size = sizeof(attr),
		.sample_period = nmi_sample_period,
		.pinned = 1,
		.disabled = 0,
	};

	return syscall(__NR_perf_event_open, &attr, -1, cpu, -1, 0);
}

struct conctest_ctx {
	pthread_t *threads;
	struct task_ctx *task_ctxs;
	int nr_threads;

	int *nmi_link_fds;
	int *nmi_pmu_fds;
	int nr_nmis;

	struct bpf_link **attach_links;
	int nr_attach_links;
	int max_attach_links;
};

static struct conctest_ctx *alloc_ctx(int nr_cpus, struct conctest_cfg *cfgs)
{
	int nr_task = 0, nr_nmi = 0, nr_attach = 0;
	struct conctest_ctx *ctx;

	for_each_conctest_cfg(cfg, cfgs) {
		switch (cfg->type) {
		case CT_TASK_PROG:
			nr_task++;
			break;
		case CT_NMI_PROG:
			nr_nmi++;
			break;
		case CT_ATTACH_PROG:
			nr_attach++;
			break;
		default:
			break;
		}
	}

	if (nr_task > 1) {
		fprintf(stderr, "Only one CT_TASK_PROG entry allowed\n");
		return NULL;
	}

	if (nr_nmi > 1) {
		fprintf(stderr, "Only one CT_NMI_PROG entry allowed\n");
		return NULL;
	}

	if (nr_attach > MAX_ATTACH_LINKS) {
		fprintf(stderr, "Too many attach links (%d > %d)\n", nr_attach,
			MAX_ATTACH_LINKS);
		return NULL;
	}

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	if (nr_task) {
		ctx->threads = calloc(nr_cpus, sizeof(*ctx->threads));
		ctx->task_ctxs = calloc(nr_cpus, sizeof(*ctx->task_ctxs));
		if (!ctx->threads || !ctx->task_ctxs)
			goto err;
	}

	if (nr_nmi) {
		ctx->nmi_link_fds = malloc(nr_cpus * sizeof(*ctx->nmi_link_fds));
		ctx->nmi_pmu_fds = malloc(nr_cpus * sizeof(*ctx->nmi_pmu_fds));
		if (!ctx->nmi_link_fds || !ctx->nmi_pmu_fds)
			goto err;
		memset(ctx->nmi_link_fds, -1, nr_cpus * sizeof(*ctx->nmi_link_fds));
		memset(ctx->nmi_pmu_fds, -1, nr_cpus * sizeof(*ctx->nmi_pmu_fds));
	}

	if (nr_attach) {
		ctx->attach_links = calloc(nr_attach, sizeof(*ctx->attach_links));
		if (!ctx->attach_links)
			goto err;
		ctx->max_attach_links = nr_attach;
	}

	return ctx;

err:
	free(ctx->threads);
	free(ctx->task_ctxs);
	free(ctx->nmi_link_fds);
	free(ctx->nmi_pmu_fds);
	free(ctx->attach_links);
	free(ctx);
	return NULL;
}

static void free_ctx(struct conctest_ctx *ctx)
{
	int i;

	if (!ctx)
		return;

	for (i = 0; i < ctx->nr_nmis; i++) {
		if (ctx->nmi_link_fds[i] >= 0)
			close(ctx->nmi_link_fds[i]);
		if (ctx->nmi_pmu_fds[i] >= 0)
			close(ctx->nmi_pmu_fds[i]);
	}

	for (i = 0; i < ctx->nr_attach_links; i++)
		bpf_link__destroy(ctx->attach_links[i]);

	for (i = 0; i < ctx->nr_threads; i++)
		pthread_join(ctx->threads[i], NULL);

	free(ctx->threads);
	free(ctx->task_ctxs);
	free(ctx->nmi_link_fds);
	free(ctx->nmi_pmu_fds);
	free(ctx->attach_links);
	free(ctx);
}

static void dump_prog_stdout(struct conctest *skel)
{
	LIBBPF_OPTS(bpf_prog_stream_read_opts, ropts);
	struct bpf_program *prog;
	char buf[4096];
	int fd, ret;

	bpf_object__for_each_program(prog, skel->obj) {
		int printed_header = 0;

		fd = bpf_program__fd(prog);
		if (fd < 0)
			continue;

		for (;;) {
			ret = bpf_prog_stream_read(fd, BPF_STREAM_STDOUT, buf,
						   sizeof(buf) - 1, &ropts);
			if (ret <= 0)
				break;

			if (!printed_header) {
				printf("\n=== %s stdout: ===\n", bpf_program__name(prog));
				printed_header = 1;
			}

			buf[ret] = '\0';
			printf("%s", buf);
		}
	}
}

static int find_prog_fd(struct conctest *skel, const char *prog_name)
{
	struct bpf_program *prog;

	prog = bpf_object__find_program_by_name(skel->obj, prog_name);
	if (!prog)
		return -1;
	return bpf_program__fd(prog);
}

static int run_test(struct conctest_test *test, int nr_cpus, int duration)
{
	struct conctest_ctx *ctx;
	struct conctest *skel;
	int err = -1;

	if (test->nr_cpus > 0)
		nr_cpus = test->nr_cpus;

	ctx = alloc_ctx(nr_cpus, test->cfgs);
	if (!ctx)
		return -ENOMEM;

	printf("Running test '%s' on %d CPU(s) for %d seconds\n", test->name, nr_cpus, duration);

	skel = conctest__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		goto free;
	}

	for_each_conctest_cfg(cfg, test->cfgs) {
		struct bpf_program *prog;
		const char *name = NULL;

		switch (cfg->type) {
		case CT_TASK_PROG:
			name = cfg->task.prog_name;
			break;
		case CT_NMI_PROG:
			name = cfg->nmi.prog_name;
			break;
		case CT_ATTACH_PROG:
			cfg->attach.get_prog(skel, cfg, false);
			break;
		default:
			break;
		}

		if (name) {
			prog = bpf_object__find_program_by_name(skel->obj, name);
			if (!prog) {
				fprintf(stderr, "Program '%s' not found\n", name);
				goto out;
			}
			bpf_program__set_autoload(prog, true);
		}
	}

	err = conctest__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
		goto out;
	}

	stop = 0;

	if (test->init)
		test->init(skel);
	/* Pass the test nr_cpus to rotate between objects, but use passed in nr_cpus otherwise. */
	skel->bss->nr_cpus = test->nr_cpus;
	skel->bss->delay_seed = delay_us;

	for_each_conctest_cfg(cfg, test->cfgs) {
		int cpu;

		switch (cfg->type) {
		case CT_TASK_PROG:
			for (cpu = 0; cpu < nr_cpus; cpu++) {
				struct task_ctx *tc;
				int prog_fd;

				prog_fd = find_prog_fd(skel, cfg->task.prog_name);
				if (prog_fd < 0) {
					fprintf(stderr,
						"Failed to get task prog fd for CPU %d\n", cpu);
					goto out;
				}

				tc = &ctx->task_ctxs[ctx->nr_threads];
				tc->prog_fd = prog_fd;
				tc->cpu = cpu;
				err = pthread_create(&ctx->threads[ctx->nr_threads], NULL,
						     worker, tc);
				if (err) {
					fprintf(stderr,
						"Failed to create thread for CPU %d: %s\n",
						cpu, strerror(err));
					goto out;
				}
				ctx->nr_threads++;
			}
			break;
		case CT_NMI_PROG:
			for (cpu = 0; cpu < nr_cpus; cpu++) {
				int prog_fd, pmu_fd, link_fd;
				int idx = ctx->nr_nmis;

				prog_fd = find_prog_fd(skel, cfg->nmi.prog_name);
				if (prog_fd < 0) {
					fprintf(stderr,
						"Failed to get NMI prog fd for CPU %d\n", cpu);
					goto out;
				}

				pmu_fd = open_perf_event(cpu);
				if (pmu_fd < 0) {
					fprintf(stderr,
						"Failed to open perf event on CPU %d: %s\n",
						cpu, strerror(errno));
					goto out;
				}
				ctx->nmi_pmu_fds[idx] = pmu_fd;

				link_fd = bpf_link_create(prog_fd, pmu_fd, BPF_PERF_EVENT, NULL);
				if (link_fd < 0) {
					fprintf(stderr,
						"Failed to attach NMI prog on CPU %d: %s\n",
						cpu, strerror(errno));
					ctx->nr_nmis++;
					goto out;
				}
				ctx->nmi_link_fds[idx] = link_fd;
				ctx->nr_nmis++;
			}
			break;
		case CT_ATTACH_PROG: {
			struct bpf_program *prog;
			struct bpf_link *link;

			if (ctx->nr_attach_links >= ctx->max_attach_links) {
				fprintf(stderr, "Too many attach links\n");
				goto out;
			}

			prog = cfg->attach.get_prog(skel, cfg, true);
			if (!prog) {
				fprintf(stderr, "Failed to get attach prog\n");
				goto out;
			}

			link = bpf_program__attach_tracepoint(prog, cfg->attach.tp_category,
							      cfg->attach.tp_name);
			if (!link) {
				fprintf(stderr, "Failed to attach prog: %s\n",
					strerror(errno));
				goto out;
			}
			ctx->attach_links[ctx->nr_attach_links++] = link;
			break;
		}
		default:
			break;
		}
	}

	sleep(duration);
	printf("Test '%s' completed\n", test->name);
	err = 0;
out:
	stop = 1;
	if (dump_test_stats(skel))
		err = -1;
	dump_prog_stdout(skel);
	printf("Test '%s': %s\n", test->name, err ? "FAIL" : "PASS");
	conctest__destroy(skel);
free:
	free_ctx(ctx);
	return err;
}

static const char *test_filter[MAX_FILTERS];
static int nr_test_filters;

static int parse_test_filter(char *arg)
{
	char *token;

	token = strtok(arg, ",");
	while (token) {
		if (nr_test_filters >= MAX_FILTERS) {
			fprintf(stderr, "Too many test filters (max %d)\n", MAX_FILTERS);
			return -1;
		}
		test_filter[nr_test_filters++] = token;
		token = strtok(NULL, ",");
	}
	return 0;
}

static int test_selected(const char *name)
{
	int i;

	if (!nr_test_filters)
		return 1;

	for (i = 0; i < nr_test_filters; i++) {
		if (strncmp(test_filter[i], name, strlen(test_filter[i])) == 0)
			return 1;
	}
	return 0;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [OPTIONS]\n"
		"  -h         Show this help message\n"
		"  -t TESTS   Comma-separated list of test names to run\n"
		"  -c CPUS    Number of CPUs/threads (default: %d)\n"
		"  -d SECS    Duration per test in seconds (default: %d)\n"
		"  -s PERIOD  NMI perf sample period (default: %d)\n"
		"  -S SEED    Delay seed for reproducibility (default: random)\n"
		"  -D USECS   Max critical section delay in us (default: 10)\n"
		"  -v         Verbose output\n",
		prog, DEFAULT_NR_CPUS, DEFAULT_DURATION, NMI_SAMPLE_PERIOD);
}

int main(int argc, char **argv)
{
	int max_cpus = libbpf_num_possible_cpus();
	int duration = DEFAULT_DURATION;
	int nr_cpus = DEFAULT_NR_CPUS;
	int opt, ran = 0, failed = 0;
	struct conctest_test *test;

	if (max_cpus < 0) {
		fprintf(stderr, "Failed to get number of possible CPUs\n");
		return 1;
	}

	while ((opt = getopt(argc, argv, "ht:c:d:s:S:D:v")) != -1) {
		switch (opt) {
		case 't':
			if (parse_test_filter(optarg))
				return 1;
			break;
		case 'c':
			nr_cpus = atoi(optarg);
			if (nr_cpus < 1 || nr_cpus > max_cpus) {
				fprintf(stderr, "Invalid CPU count (1-%d)\n", max_cpus);
				return 1;
			}
			break;
		case 'd':
			duration = atoi(optarg);
			if (duration < 1) {
				fprintf(stderr, "Invalid duration\n");
				return 1;
			}
			break;
		case 's':
			nmi_sample_period = atoi(optarg);
			if (nmi_sample_period < 1) {
				fprintf(stderr, "Invalid sample period\n");
				return 1;
			}
			break;
		case 'v':
			verbose = 1;
			break;
		case 'D':
			delay_max_us = (__u32)atoi(optarg);
			break;
		case 'S':
			delay_seed = (__u32)strtoul(optarg, NULL, 0);
			break;
		case 'h':
		default:
			usage(argv[0]);
			return opt == 'h' ? 0 : 1;
		}
	}

	if (!delay_seed)
		delay_seed = (__u32)time(NULL);
	delay_us = delay_seed % (delay_max_us + 1);
	printf("Seed: %u, delay: %u us (max: %u us)\n", delay_seed, delay_us, delay_max_us);

	for (test = all_tests; test->name; test++) {
		if (!test_selected(test->name))
			continue;

		ran++;
		if (run_test(test, nr_cpus, duration))
			failed++;
		fprintf(stderr, "\n\n\n");
	}

	if (!ran)
		printf("No tests matched\n");
	else
		printf("\n%d/%d tests passed\n", ran - failed, ran);

	return failed > 0 ? 1 : 0;
}
