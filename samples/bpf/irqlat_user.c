// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022 Kylin
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <linux/perf_event.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "trace_helpers.h"

#define MAX_CPUS 128
static int map_fd[2];

struct datares {
	__u64 entries;
	__u64 total;
	__u64 max;
	__u64 min;
};

static void get_data(int fd)
{
	int i;
	struct datares res;
	__u64 avg;

	/* Clear screen */
	printf("\033[2J");

	/* Header */
	printf("\nirq Latency statistics: (ns)\n");
	for (i = 0; i < MAX_CPUS; i++) {
		bpf_map_lookup_elem(fd, &i, &res);

		if (res.entries == 0)
			continue;

		avg = res.total / res.entries;
		printf("cpu:%d, max:%llu, min:%llu, avg:%llu\n",
					i, res.max, res.min, avg);
	}
}

int main(int argc, char **argv)
{
	char filename[256];
	struct bpf_object *obj = NULL;
	struct bpf_link *links[2];
	struct bpf_program *prog;
	int delay = 1, i = 0;

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		obj = NULL;
		goto cleanup;
	}

	/* load BPF program */
	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup;
	}

	map_fd[0] = bpf_object__find_map_fd_by_name(obj, "irq_ts");
	map_fd[1] = bpf_object__find_map_fd_by_name(obj, "irq_lat");
	if (map_fd[0] < 0 || map_fd[1] < 0) {
		fprintf(stderr, "ERROR: finding a map in obj file failed\n");
		goto cleanup;
	}

	bpf_object__for_each_program(prog, obj) {
		links[i] = bpf_program__attach(prog);
		if (libbpf_get_error(links[i])) {
			fprintf(stderr, "ERROR: bpf_program__attach failed\n");
			links[i] = NULL;
			goto cleanup;
		}
		i++;
	}

	while (1) {
		sleep(delay);
		get_data(map_fd[1]);
	}

cleanup:
	for (i--; i >= 0; i--)
		bpf_link__destroy(links[i]);

	bpf_object__close(obj);
	return 0;
}
