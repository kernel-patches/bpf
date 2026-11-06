/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Radu Toader
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <signal.h>
#include <assert.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "scx_tickbug.bpf.skel.h"

const char help_fmt[] =
"Hold a task runnable on a CPU that is in the idle loop.\n"
"\n"
"Tasks named \"spin\" are queued on the target CPU's run queue and left\n"
"there, so the CPU idles with a runnable task queued, until a periodic\n"
"timer releases one. Every other task runs through a shared DSQ.\n"
"\n"
"See the top-level comment in .bpf.c for more details.\n"
"\n"
"Usage: %s [-c CPU] [-t CPU] [-H HOLD_MS] [-s SLICE_US] [-v]\n"
"\n"
"  -c CPU        Target CPU, the one that idles with a task queued (default: 0)\n"
"  -t CPU        CPU the release timer is pinned to (default: 1)\n"
"  -H HOLD_MS    How long a task is held before release (default: 10)\n"
"  -s SLICE_US   Override slice duration\n"
"  -v            Print libbpf debug messages\n"
"  -h            Display this help and exit\n";

static bool verbose;
static volatile int exit_req;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sigint_handler(int dummy)
{
	exit_req = 1;
}

int main(int argc, char **argv)
{
	struct scx_tickbug *skel;
	struct bpf_link *link;
	__u64 seq = 0, ecode;
	__u32 nr_cpu_ids;
	__s32 opt;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
restart:
	optind = 1;
	skel = SCX_OPS_OPEN(tickbug_ops, scx_tickbug);

	nr_cpu_ids = libbpf_num_possible_cpus();
	assert(nr_cpu_ids > 0);
	assert(nr_cpu_ids <= INT32_MAX);

	skel->rodata->target_cpu = 0;
	skel->rodata->timer_cpu = 1;
	skel->rodata->hold_ns = 10ULL * 1000 * 1000;
	skel->rodata->slice_ns = __COMPAT_ENUM_OR_ZERO("scx_public_consts", "SCX_SLICE_DFL");

	while ((opt = getopt(argc, argv, "c:t:H:s:vh")) != -1) {
		switch (opt) {
		case 'c':
		case 't': {
			unsigned long cpu = strtoul(optarg, NULL, 0);

			if (cpu >= nr_cpu_ids) {
				fprintf(stderr, "invalid CPU id %lu (%u max)\n",
					cpu, nr_cpu_ids - 1);
				scx_tickbug__destroy(skel);
				return 1;
			}
			if (opt == 'c')
				skel->rodata->target_cpu = (s32)cpu;
			else
				skel->rodata->timer_cpu = (s32)cpu;
			break;
		}
		case 'H':
			skel->rodata->hold_ns = strtoull(optarg, NULL, 0) * 1000 * 1000;
			break;
		case 's':
			skel->rodata->slice_ns = strtoull(optarg, NULL, 0) * 1000;
			break;
		case 'v':
			verbose = true;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			scx_tickbug__destroy(skel);
			return opt != 'h';
		}
	}

	if (skel->rodata->target_cpu >= (s32)nr_cpu_ids ||
	    skel->rodata->timer_cpu >= (s32)nr_cpu_ids) {
		fprintf(stderr, "need CPUs 0 and 1 to exist: target %d, timer %d, %u online\n",
			skel->rodata->target_cpu, skel->rodata->timer_cpu, nr_cpu_ids);
		scx_tickbug__destroy(skel);
		return 1;
	}
	if (skel->rodata->target_cpu == skel->rodata->timer_cpu) {
		fprintf(stderr, "the target CPU and the timer CPU must differ (both %d)\n",
			skel->rodata->target_cpu);
		scx_tickbug__destroy(skel);
		return 1;
	}
	if (!skel->rodata->hold_ns) {
		fprintf(stderr, "a hold of 0 would not hold anything\n");
		scx_tickbug__destroy(skel);
		return 1;
	}

	SCX_OPS_LOAD(skel, tickbug_ops, scx_tickbug, uei);
	link = SCX_OPS_ATTACH(skel, tickbug_ops, scx_tickbug);

	printf("target_cpu=%d timer_cpu=%d hold_ms=%llu slice_us=%llu\n",
	       skel->rodata->target_cpu, skel->rodata->timer_cpu,
	       (unsigned long long)(skel->rodata->hold_ns / 1000000),
	       (unsigned long long)(skel->rodata->slice_ns / 1000));

	if (!skel->data->timer_pinned)
		printf("WARNING: BPF_F_TIMER_CPU_PIN unavailable, release timer is not pinned\n");

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		__u64 released = skel->bss->nr_released;

		printf("[SEQ %llu]\n", seq++);
		printf("enq    :%10" PRIu64 "   held:%10" PRIu64
		       " released:%10" PRIu64 " timers:%10" PRIu64 "\n",
		       skel->bss->nr_enq, skel->bss->nr_held,
		       skel->bss->nr_released, skel->bss->nr_timers);
		printf("pass   :%10" PRIu64 "  local:%10" PRIu64
		       "     lost:%10" PRIu64 " othrcpu:%10" PRIu64
		       " overflow:%10" PRIu64 " requeue:%10" PRIu64 "\n",
		       skel->bss->nr_passthru, skel->bss->nr_locals,
		       skel->bss->nr_lost, skel->bss->nr_other_cpu,
		       skel->bss->nr_overflow, skel->bss->nr_requeue);
		printf("last   :%10" PRIu64 "    dup:%10" PRIu64
		       "    stale:%10" PRIu64 "  undone:%10" PRIu64
		       "      now:%10" PRIu64 "\n",
		       skel->bss->nr_last, skel->bss->nr_dup,
		       skel->bss->nr_stale, skel->bss->nr_undone,
		       skel->bss->nr_held_now);
		/*
		 * The mean and the worst hold are the independent variable of
		 * the whole experiment: without them the run proves nothing.
		 */
		printf("hold_us: mean %8llu   max %8llu\n",
		       (unsigned long long)(released ?
			       (skel->bss->total_held_ns / released) / 1000 : 0),
		       (unsigned long long)(skel->bss->max_held_ns / 1000));
		fflush(stdout);
		sleep(1);
	}

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_tickbug__destroy(skel);

	if (!exit_req && UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}
