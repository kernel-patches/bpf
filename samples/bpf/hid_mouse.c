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
#include <linux/errno.h>

#include "bpf_util.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "hid_mouse.skel.h"

static bool running = true;

struct attach_prog_args {
	int prog_fd;
	unsigned int hid;
	int retval;
};

static void int_exit(int sig)
{
	running = false;
	exit(0);
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"%s: %s /sys/bus/hid/devices/0BUS:0VID:0PID:00ID\n\n",
		__func__, prog);
}

static int get_hid_id(const char *path)
{
	const char *str_id, *dir;
	char uevent[1024];
	int fd;

	memset(uevent, 0, sizeof(uevent));
	snprintf(uevent, sizeof(uevent) - 1, "%s/uevent", path);

	fd = open(uevent, O_RDONLY | O_NONBLOCK);
	if (fd < 0)
		return -ENOENT;

	close(fd);

	dir = basename((char *)path);

	str_id = dir + sizeof("0003:0001:0A37.");
	return (int)strtol(str_id, NULL, 16);
}

int main(int argc, char **argv)
{
	struct hid_mouse_lskel *skel;
	struct bpf_program *prog;
	int err;
	const char *optstr = "";
	const char *sysfs_path;
	int opt, hid_id, attach_fd;
	struct attach_prog_args args = {
		.retval = -1,
	};
	DECLARE_LIBBPF_OPTS(bpf_test_run_opts, tattr,
			    .ctx_in = &args,
			    .ctx_size_in = sizeof(args),
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

	hid_id = get_hid_id(sysfs_path);

	if (hid_id < 0) {
		fprintf(stderr, "can not open HID device: %m\n");
		return 1;
	}
	args.hid = hid_id;

	attach_fd = bpf_program__fd(skel->progs.attach_prog);
	if (attach_fd < 0) {
		fprintf(stderr, "can't locate attach prog: %m\n");
		return 1;
	}

	bpf_object__for_each_program(prog, *skel->skeleton->obj) {
		/* ignore syscalls */
		if (bpf_program__get_type(prog) != BPF_PROG_TYPE_TRACING)
			continue;

		args.retval = -1;
		args.prog_fd = bpf_program__fd(prog);
		err = bpf_prog_test_run_opts(attach_fd, &tattr);
		if (err) {
			fprintf(stderr, "can't attach prog to hid device %d: %m (err: %d)\n",
				hid_id, err);
			return 1;
		}
	}

	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);

	while (running)
		;

	hid_mouse_lskel__destroy(skel);

	return 0;
}
