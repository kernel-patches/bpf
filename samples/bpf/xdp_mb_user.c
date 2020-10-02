// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All rights reserved.
 */
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/resource.h>
#include <net/if.h>

#include "bpf_util.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

static __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;
static __u32 prog_id;
static int rx_cnt_fd, tot_len_fd, rx_frags_fd;
static int ifindex;

static void int_exit(int sig)
{
	__u32 curr_prog_id = 0;

	if (bpf_get_link_xdp_id(ifindex, &curr_prog_id, xdp_flags)) {
		printf("bpf_get_link_xdp_id failed\n");
		exit(1);
	}
	if (prog_id == curr_prog_id)
		bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
	else if (!curr_prog_id)
		printf("couldn't find a prog id on a given interface\n");
	else
		printf("program on interface changed, not removing\n");
	exit(0);
}

/* count total packets and bytes per second */
static void poll_stats(int interval)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	__u64 rx_frags_cnt[nr_cpus], rx_frags_cnt_prev[nr_cpus];
	__u64 tot_len[nr_cpus], tot_len_prev[nr_cpus];
	__u64 rx_cnt[nr_cpus], rx_cnt_prev[nr_cpus];
	int i;

	memset(rx_frags_cnt_prev, 0, sizeof(rx_frags_cnt_prev));
	memset(tot_len_prev, 0, sizeof(tot_len_prev));
	memset(rx_cnt_prev, 0, sizeof(rx_cnt_prev));

	while (1) {
		__u64 n_rx_pkts = 0, rx_frags = 0, rx_len = 0;
		__u32 key = 0;

		sleep(interval);

		/* fetch rx cnt */
		assert(bpf_map_lookup_elem(rx_cnt_fd, &key, rx_cnt) == 0);
		for (i = 0; i < nr_cpus; i++)
			n_rx_pkts += (rx_cnt[i] - rx_cnt_prev[i]);
		memcpy(rx_cnt_prev, rx_cnt, sizeof(rx_cnt));

		/* fetch rx frags */
		assert(bpf_map_lookup_elem(rx_frags_fd, &key, rx_frags_cnt) == 0);
		for (i = 0; i < nr_cpus; i++)
			rx_frags += (rx_frags_cnt[i] - rx_frags_cnt_prev[i]);
		memcpy(rx_frags_cnt_prev, rx_frags_cnt, sizeof(rx_frags_cnt));

		/* count total bytes of packets */
		assert(bpf_map_lookup_elem(tot_len_fd, &key, tot_len) == 0);
		for (i = 0; i < nr_cpus; i++)
			rx_len += (tot_len[i] - tot_len_prev[i]);
		memcpy(tot_len_prev, tot_len, sizeof(tot_len));

		if (n_rx_pkts)
			printf("ifindex %i: %10llu pkt/s, %10llu frags/s, %10llu bytes/s\n",
			       ifindex, n_rx_pkts / interval, rx_frags / interval,
			       rx_len / interval);
	}
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"%s: %s [OPTS] IFACE\n\n"
		"OPTS:\n"
		"    -F    force loading prog\n",
		__func__, prog);
}

int main(int argc, char **argv)
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type	= BPF_PROG_TYPE_XDP,
	};
	int prog_fd, opt;
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	const char *optstr = "F";
	struct bpf_program *prog;
	struct bpf_object *obj;
	char filename[256];
	int err;

	while ((opt = getopt(argc, argv, optstr)) != -1) {
		switch (opt) {
		case 'F':
			xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
			break;
		default:
			usage(basename(argv[0]));
			return 1;
		}
	}

	if (optind == argc) {
		usage(basename(argv[0]));
		return 1;
	}

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		perror("setrlimit(RLIMIT_MEMLOCK)");
		return 1;
	}

	ifindex = if_nametoindex(argv[optind]);
	if (!ifindex) {
		perror("if_nametoindex");
		return 1;
	}

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	prog_load_attr.file = filename;

	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd))
		return 1;

	prog = bpf_program__next(NULL, obj);
	if (!prog) {
		printf("finding a prog in obj file failed\n");
		return 1;
	}

	if (!prog_fd) {
		printf("bpf_prog_load_xattr: %s\n", strerror(errno));
		return 1;
	}

	rx_cnt_fd = bpf_object__find_map_fd_by_name(obj, "rx_cnt");
	rx_frags_fd = bpf_object__find_map_fd_by_name(obj, "rx_frags");
	tot_len_fd = bpf_object__find_map_fd_by_name(obj, "tot_len");
	if (rx_cnt_fd < 0 || rx_frags_fd < 0 || tot_len_fd < 0) {
		printf("bpf_object__find_map_fd_by_name failed\n");
		return 1;
	}

	if (bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags) < 0) {
		printf("ERROR: link set xdp fd failed on %d\n", ifindex);
		return 1;
	}

	err = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
	if (err) {
		printf("can't get prog info - %s\n", strerror(errno));
		return err;
	}
	prog_id = info.id;

	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);

	poll_stats(1);

	return 0;
}
