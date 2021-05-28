/* SPDX-License-Identifier: GPL-2.0
 * Copyright(c) 2017 Jesper Dangaard Brouer, Red Hat, Inc.
 */
static const char *__doc__=
 "XDP monitor tool, based on tracepoints\n"
;

static const char *__doc_err_only__=
 " NOTICE: Only tracking XDP redirect errors\n"
 "         Enable TX success stats via '--stats'\n"
 "         (which comes with a per packet processing overhead)\n"
;

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <locale.h>

#include <sys/resource.h>
#include <getopt.h>
#include <net/if.h>
#include <time.h>

#include <signal.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "bpf_util.h"
#include "xdp_sample_user.h"

static bool debug = false;
struct bpf_object *obj;

static const struct option long_options[] = {
	{"help",	no_argument,		NULL, 'h' },
	{"debug",	no_argument,		NULL, 'D' },
	{"stats",	no_argument,		NULL, 's' },
	{"interval",	required_argument,	NULL, 'i' },
	{"verbose",	no_argument,		NULL, 'v' },
	{}
};

static void int_exit(int sig)
{
	bpf_object__close(obj);
	sample_exit(EXIT_OK);
}

/* C standard specifies two constants, EXIT_SUCCESS(0) and EXIT_FAILURE(1) */
#define EXIT_FAIL_MEM	5

static void usage(char *argv[])
{
	int i;
	printf("\nDOCUMENTATION:\n%s\n", __doc__);
	printf("\n");
	printf(" Usage: %s (options-see-below)\n",
	       argv[0]);
	printf(" Listing options:\n");
	for (i = 0; long_options[i].name != 0; i++) {
		printf(" --%-15s", long_options[i].name);
		if (long_options[i].flag != NULL)
			printf(" flag (internal value:%d)",
			       *long_options[i].flag);
		else
			printf("short-option: -%c",
			       long_options[i].val);
		printf("\n");
	}
	printf("\n");
}

static void print_bpf_prog_info(void)
{
	struct bpf_program *prog;
	struct bpf_map *map;
	int i = 0;

	/* Prog info */
	printf("Loaded BPF prog have %d bpf program(s)\n", tp_cnt);
	bpf_object__for_each_program(prog, obj) {
		printf(" - prog_fd[%d] = fd(%d)\n", i, bpf_program__fd(prog));
		i++;
	}

	i = 0;
	/* Maps info */
	printf("Loaded BPF prog have %d map(s)\n", NUM_MAP);
	bpf_object__for_each_map(map, obj) {
		const char *name = bpf_map__name(map);
		int fd		 = bpf_map__fd(map);

		printf(" - map_data[%d] = fd(%d) name:%s\n", i, fd, name);
		i++;
	}

	/* Event info */
	printf("Searching for (max:%d) event file descriptor(s)\n", tp_cnt);
	for (i = 0; i < tp_cnt; i++) {
		int fd = bpf_link__fd(tp_links[i]);

		if (fd != -1)
			printf(" - event_fd[%d] = fd(%d)\n", i, fd);
	}
}

int main(int argc, char **argv)
{
	int mask = SAMPLE_REDIRECT_ERR_CNT | SAMPLE_CPUMAP_ENQUEUE_CNT |
		   SAMPLE_CPUMAP_KTHREAD_CNT | SAMPLE_EXCEPTION_CNT |
		   SAMPLE_DEVMAP_XMIT_CNT;
	int longindex = 0, opt;
	int ret = EXIT_FAILURE;
	char filename[256];

	/* Default settings: */
	bool errors_only = true;
	int interval = 2;

	/* Parse commands line args */
	while ((opt = getopt_long(argc, argv, "hDi:vs",
				  long_options, &longindex)) != -1) {
		switch (opt) {
		case 'D':
			debug = true;
			break;
		case 's':
			errors_only = false;
			break;
		case 'i':
			interval = atoi(optarg);
			break;
		case 'v':
			sample_log_level ^= LL_DEBUG - 1;
			break;
		case 'h':
		default:
			usage(argv);
			return ret;
		}
	}

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	/* Remove tracepoint program when program is interrupted or killed */
	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);

	obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj)) {
		printf("ERROR: opening BPF object file failed\n");
		obj = NULL;
		goto cleanup;
	}

	/* load BPF program */
	if (bpf_object__load(obj)) {
		printf("ERROR: loading BPF object file failed\n");
		goto cleanup;
	}

	if (sample_init(obj) < 0) {
		fprintf(stderr, "Failed to initialize sample\n");
		goto cleanup;
	}

	if (debug) {
		print_bpf_prog_info();
	}

	/* Unload/stop tracepoint event by closing bpf_link's */
	if (errors_only) {
		printf("%s", __doc_err_only__);

		/* The bpf_link[i] depend on the order of
		 * the functions was defined in _kern.c
		 */
		bpf_link__destroy(tp_links[2]);	/* tracepoint/xdp/xdp_redirect */
		tp_links[2] = NULL;

		bpf_link__destroy(tp_links[3]);	/* tracepoint/xdp/xdp_redirect_map */
		tp_links[3] = NULL;
	} else {
		mask |= SAMPLE_REDIRECT_CNT;
	}

	sample_stats_poll(interval, mask, NULL, true);

cleanup:
	bpf_object__close(obj);
	sample_exit(EXIT_OK);
}
