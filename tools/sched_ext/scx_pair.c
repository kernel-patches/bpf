/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include "scx_common.h"
#include "scx_pair.h"
#include "scx_pair.skel.h"

const char help_fmt[] =
"A demo sched_ext core-scheduler which always makes every sibling CPU pair\n"
"execute from the same CPU cgroup.\n"
"\n"
"See the top-level comment in .bpf.c for more details.\n"
"\n"
"Usage: %s [-S STRIDE] [-p]\n"
"\n"
"  -S STRIDE     Override CPU pair stride (default: nr_cpus_ids / 2)\n"
"  -p            Switch only tasks on SCHED_EXT policy intead of all\n"
"  -h            Display this help and exit\n";

static volatile int exit_req;

static void sigint_handler(int dummy)
{
	exit_req = 1;
}

int main(int argc, char **argv)
{
	struct scx_pair *skel;
	struct bpf_link *link;
	__u64 seq = 0;
	__s32 stride, i, opt, outer_fd;

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	skel = scx_pair__open();
	SCX_BUG_ON(!skel, "Failed to open skel");

	skel->rodata->nr_cpu_ids = libbpf_num_possible_cpus();

	/* pair up the earlier half to the latter by default, override with -s */
	stride = skel->rodata->nr_cpu_ids / 2;

	while ((opt = getopt(argc, argv, "S:ph")) != -1) {
		switch (opt) {
		case 'S':
			stride = strtoul(optarg, NULL, 0);
			break;
		case 'p':
			skel->rodata->switch_partial = true;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	bpf_map__set_max_entries(skel->maps.pair_ctx, skel->rodata->nr_cpu_ids / 2);

	/* Resize arrays so their element count is equal to cpu count. */
	RESIZE_ARRAY(rodata, pair_cpu, skel->rodata->nr_cpu_ids);
	RESIZE_ARRAY(rodata, pair_id, skel->rodata->nr_cpu_ids);
	RESIZE_ARRAY(rodata, in_pair_idx, skel->rodata->nr_cpu_ids);

	for (i = 0; i < skel->rodata->nr_cpu_ids; i++)
		skel->rodata_pair_cpu->pair_cpu[i] = -1;

	printf("Pairs: ");
	for (i = 0; i < skel->rodata->nr_cpu_ids; i++) {
		int j = (i + stride) % skel->rodata->nr_cpu_ids;

		if (skel->rodata_pair_cpu->pair_cpu[i] >= 0)
			continue;

		SCX_BUG_ON(i == j,
			   "Invalid stride %d - CPU%d wants to be its own pair",
			   stride, i);

		SCX_BUG_ON(skel->rodata_pair_cpu->pair_cpu[j] >= 0,
			   "Invalid stride %d - three CPUs (%d, %d, %d) want to be a pair",
			   stride, i, j, skel->rodata_pair_cpu->pair_cpu[j]);

		skel->rodata_pair_cpu->pair_cpu[i] = j;
		skel->rodata_pair_cpu->pair_cpu[j] = i;
		skel->rodata_pair_id->pair_id[i] = i;
		skel->rodata_pair_id->pair_id[j] = i;
		skel->rodata_in_pair_idx->in_pair_idx[i] = 0;
		skel->rodata_in_pair_idx->in_pair_idx[j] = 1;

		printf("[%d, %d] ", i, j);
	}
	printf("\n");

	SCX_BUG_ON(scx_pair__load(skel), "Failed to load skel");

	/*
	 * Populate the cgrp_q_arr map which is an array containing per-cgroup
	 * queues. It'd probably be better to do this from BPF but there are too
	 * many to initialize statically and there's no way to dynamically
	 * populate from BPF.
	 */
	outer_fd = bpf_map__fd(skel->maps.cgrp_q_arr);
	SCX_BUG_ON(outer_fd < 0, "Failed to get outer_fd: %d", outer_fd);

	printf("Initializing");
        for (i = 0; i < MAX_CGRPS; i++) {
		__s32 inner_fd;

		if (exit_req)
			break;

		inner_fd = bpf_map_create(BPF_MAP_TYPE_QUEUE, NULL, 0,
					  sizeof(__u32), MAX_QUEUED, NULL);
		SCX_BUG_ON(inner_fd < 0, "Failed to get inner_fd: %d",
			   inner_fd);
		SCX_BUG_ON(bpf_map_update_elem(outer_fd, &i, &inner_fd, BPF_ANY),
			   "Failed to set inner map");
		close(inner_fd);

		if (!(i % 10))
			printf(".");
		fflush(stdout);
        }
	printf("\n");

	/*
	 * Fully initialized, attach and run.
	 */
	link = bpf_map__attach_struct_ops(skel->maps.pair_ops);
	SCX_BUG_ON(!link, "Failed to attach struct_ops");

	while (!exit_req && !uei_exited(&skel->bss->uei)) {
		printf("[SEQ %llu]\n", seq++);
		printf(" total:%10lu dispatch:%10lu   missing:%10lu\n",
		       skel->bss->nr_total,
		       skel->bss->nr_dispatched,
		       skel->bss->nr_missing);
		printf(" kicks:%10lu preemptions:%7lu\n",
		       skel->bss->nr_kicks,
		       skel->bss->nr_preemptions);
		printf("   exp:%10lu exp_wait:%10lu exp_empty:%10lu\n",
		       skel->bss->nr_exps,
		       skel->bss->nr_exp_waits,
		       skel->bss->nr_exp_empty);
		printf("cgnext:%10lu   cgcoll:%10lu   cgempty:%10lu\n",
		       skel->bss->nr_cgrp_next,
		       skel->bss->nr_cgrp_coll,
		       skel->bss->nr_cgrp_empty);
		fflush(stdout);
		sleep(1);
	}

	bpf_link__destroy(link);
	uei_print(&skel->bss->uei);
	scx_pair__destroy(skel);
	return 0;
}
