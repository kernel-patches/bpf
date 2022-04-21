// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2022 Benjamin Tissoires
 */

/* not sure why but this doesn't get preoperly imported */
#define __must_check

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <linux/err.h>

#include "bpf_util.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "hid_mouse.skel.h"

static char *sysfs_path;
static int sysfs_fd;
static int prog_count;

static bool running = true;

struct prog {
	int fd;
	struct bpf_link *link;
	enum bpf_attach_type type;
};

static struct prog progs[10];

static void int_exit(int sig)
{
	running = false;
	exit(0);
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"%s: %s /sys/bus/hid/devices/0BUS:0VID:0PID:00ID/uevent\n\n",
		__func__, prog);
}

int main(int argc, char **argv)
{
	struct hid_mouse_lskel *skel;
	int prog_fd, err;
	const char *optstr = "";
	int opt;
	char filename[256];

	LIBBPF_OPTS(bpf_test_run_opts, topts,
		    .repeat = 1,
	);

	while ((opt = getopt(argc, argv, optstr)) != -1) {
		switch (opt) {
		default:
			usage(basename(argv[0]));
			return 1;
		}
	}

	if (optind == argc) {
		usage(basename(argv[0]));
		return 1;
	}

	sysfs_path = argv[optind];
	if (!sysfs_path) {
		perror("sysfs");
		return 1;
	}

	skel = hid_mouse_lskel__open_and_load();
	if (!skel) {
		fprintf(stderr, "%s  %s:%d", __func__, __FILE__, __LINE__);
		return -1;
	}

	err = hid_mouse_lskel__attach(skel);
	if (err)
		goto cleanup;

	//prog_fd = bpf_program__fd(skel->progs.hid_event);
	//err = bpf_prog_test_run_opts(prog_fd, &topts);

//	sysfs_fd = open(sysfs_path, O_RDONLY);
//
////	bpf_object__for_each_program(prog, obj) {
////		progs[prog_count].fd = bpf_program__fd(prog);
////		progs[prog_count].type = bpf_program__get_expected_attach_type(prog);
////		progs[prog_count].link = bpf_program__attach(prog);
////		if (libbpf_get_error(progs[prog_count].link)) {
////			fprintf(stderr, "bpf_prog_attach: err=%m\n");
////			progs[prog_count].fd = 0;
////			progs[prog_count].link = NULL;
////			goto cleanup;
////		}
////		prog_count++;
////	}
//
	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);
//
////	err = bpf_obj_get_info_by_fd(progs[0].fd, &info, &info_len);
////	if (err) {
////		printf("can't get prog info - %s\n", strerror(errno));
////		goto cleanup;
////	}
//
	while (running)
		;

 cleanup:
	hid_mouse_lskel__destroy(skel);

	return err;
}
