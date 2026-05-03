// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 KylinSoft Corporation.
 * Copyright (c) 2026 Kaitao Cheng <chengkaitao@kylinos.cn>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <ufq/common.h>
#include "ufq_simple.bpf.skel.h"

const char help_fmt[] =
"A simple ufq scheduler.\n"
"\n"
"Usage: %s [-v] [-d] [-h]\n"
"\n"
"  -v            Print version\n"
"  -d            Print libbpf debug messages\n"
"  -h            Display this help and exit\n";

#define UFQ_SIMPLE_VERSION "0.1.0"
#define TIME_INTERVAL 3
static bool verbose;
static volatile int exit_req;
__u64 old_stats[UFQ_SIMP_STAT_MAX];

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sigint_handler(int simple)
{
	exit_req = 1;
}

static void read_stats(struct ufq_simple *skel, __u64 *stats)
{
	int nr_cpus = libbpf_num_possible_cpus();
	__u64 cnts[UFQ_SIMP_STAT_MAX][nr_cpus];
	__u32 idx;

	memset(stats, 0, sizeof(stats[0]) * UFQ_SIMP_STAT_MAX);

	for (idx = 0; idx < UFQ_SIMP_STAT_MAX; idx++) {
		int ret, cpu;

		ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats),
					  &idx, cnts[idx]);
		if (ret < 0)
			continue;
		for (cpu = 0; cpu < nr_cpus; cpu++)
			stats[idx] += cnts[idx][cpu];
	}
}

int main(int argc, char **argv)
{
	struct ufq_simple *skel;
	struct bpf_link *link;
	__u32 opt;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	skel = UFQ_OPS_OPEN(ufq_simple_ops, ufq_simple);

	while ((opt = getopt(argc, argv, "vdh")) != -1) {
		switch (opt) {
		case 'v':
			printf("ufq_simple version: %s\n", UFQ_SIMPLE_VERSION);
			return 0;
		case 'd':
			verbose = true;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	UFQ_OPS_LOAD(skel, ufq_simple_ops, ufq_simple);
	link = UFQ_OPS_ATTACH(skel, ufq_simple_ops, ufq_simple);

	printf("ufq_simple loop ...\n");
	while (!exit_req) {
		__u64 stats[UFQ_SIMP_STAT_MAX];

		printf("--------------------------------\n");
		read_stats(skel, stats);
		printf("bps:%lluk  iops:%llu\n",
		       (stats[UFQ_SIMP_FINISH_SIZE] -
			old_stats[UFQ_SIMP_FINISH_SIZE]) / 1024 / TIME_INTERVAL,
		       (stats[UFQ_SIMP_FINISH_CNT] -
			old_stats[UFQ_SIMP_FINISH_CNT]) / TIME_INTERVAL);
		printf("(insert:   cnt=%llu size=%llu)\n",
			stats[UFQ_SIMP_INSERT_CNT], stats[UFQ_SIMP_INSERT_SIZE]);
		printf("(rqmerge: cnt=%llu size=%llu) (biomerge: cnt=%llu size=%llu)\n",
			stats[UFQ_SIMP_RQMERGE_CNT], stats[UFQ_SIMP_RQMERGE_SIZE],
			stats[UFQ_SIMP_BIOMERGE_CNT], stats[UFQ_SIMP_BIOMERGE_SIZE]);
		printf("(dispatch: cnt=%llu size=%llu) (finish: cnt=%llu size=%llu)\n",
			stats[UFQ_SIMP_DISPATCH_CNT], stats[UFQ_SIMP_DISPATCH_SIZE],
			stats[UFQ_SIMP_FINISH_CNT], stats[UFQ_SIMP_FINISH_SIZE]);
		memcpy(old_stats, stats, sizeof(old_stats));
		sleep(TIME_INTERVAL);
	}

	printf("ufq_simple loop exit ...\n");
	bpf_link__destroy(link);
	ufq_simple__destroy(skel);

	return 0;
}
