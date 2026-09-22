// SPDX-License-Identifier: GPL-2.0
/*
 * Userspace controller and monitor for scx_priority scheduler.
 *
 * Copyright (c) 2026 Rahad Bhuiya <rahadbhuiya2021@gmail.com>
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "scx_priority.bpf.skel.h"

const char help_fmt[] =
"A dual-queue priority sched_ext scheduler.\n"
"\n"
"Usage: %s [-i INTERVAL] [-v] [-h]\n"
"\n"
"  -i INTERVAL   Stats monitoring interval in seconds (default: 1)\n"
"  -v            Print libbpf debug messages\n"
"  -h            Display this help and exit\n";

static bool verbose;
static sig_atomic_t exit_req;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sigint_handler(int sig)
{
	exit_req = 1;
}

static void read_stats(struct scx_priority *skel, __u64 *stats)
{
	int nr_cpus = libbpf_num_possible_cpus();
	__u64 *cnts[2];
	__u32 idx;

	assert(nr_cpus > 0);
	cnts[0] = calloc(nr_cpus, sizeof(__u64));
	cnts[1] = calloc(nr_cpus, sizeof(__u64));
	if (!cnts[0] || !cnts[1]) {
		free(cnts[0]);
		free(cnts[1]);
		return;
	}

	memset(stats, 0, sizeof(stats[0]) * 2);

	for (idx = 0; idx < 2; idx++) {
		int ret, cpu;

		ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats),
					  &idx, cnts[idx]);
		if (ret < 0)
			continue;
		for (cpu = 0; cpu < nr_cpus; cpu++)
			stats[idx] += cnts[idx][cpu];
	}

	free(cnts[0]);
	free(cnts[1]);
}

int main(int argc, char **argv)
{
	struct scx_priority *skel;
	struct bpf_link *link;
	__s32 opt;
	__u64 ecode;
	int interval = 1;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

restart:
	optind = 1;
	skel = SCX_OPS_OPEN(priority_ops, scx_priority);

	while ((opt = getopt(argc, argv, "i:vh")) != -1) {
		switch (opt) {
		case 'i':
			interval = atoi(optarg);
			if (interval <= 0)
				interval = 1;
			break;
		case 'v':
			verbose = true;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	SCX_OPS_LOAD(skel, priority_ops, scx_priority, uei);
	link = SCX_OPS_ATTACH(skel, priority_ops, scx_priority);

	printf("scx_priority started (interval: %ds). Press Ctrl-C to stop.\n", interval);
	printf("%-15s %-15s %-15s\n", "HIGH_PRIO(UI)", "LOW_PRIO(BATCH)", "TOTAL_DISPATCH");

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		__u64 stats[2];

		read_stats(skel, stats);
		printf("%-15llu %-15llu %-15llu\n",
		       stats[0], stats[1], stats[0] + stats[1]);
		fflush(stdout);
		sleep(interval);
	}

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_priority__destroy(skel);

	if (!exit_req && UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}
