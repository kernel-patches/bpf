// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <getopt.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#ifndef __MEMCG_RSTAT_SIMPLE_BPF_SKEL_H__
#define u64 uint64_t
#endif

struct local_config {
	u64 threshold;
	u64 high_cgroup_id;
	bool use_below_low;
	bool use_below_min;
	unsigned int over_high_ms;
} local_config;

#include "memcg.skel.h"

static bool exiting;

static void sig_handler(int sig)
{
	exiting = true;
}

static void usage(char *name)
{
	fprintf(stderr,
		"Usage: %s --low_path=<path> --high_path=<path> \\\n"
		"          --threshold=<value> [OPTIONS]\n\n",
		name);
	fprintf(stderr, "Required arguments:\n");
	fprintf(stderr,
		"  -l, --low_path=PATH    Low priority memcgroup path\n");
	fprintf(stderr,
		"  -g, --high_path=PATH   High priority memcgroup path\n");
	fprintf(stderr,
		"  -t, --threshold=VALUE  The sum of 'val' PGSCAN of\n");
	fprintf(stderr,
		"                         high priority memcgroup in\n");
	fprintf(stderr,
		"                         1 sec to trigger low priority\n");
	fprintf(stderr,
		"                         cgroup over_high\n\n");
	fprintf(stderr, "Optional arguments:\n");
	fprintf(stderr, "  -o, --over_high_ms=VALUE\n");
	fprintf(stderr,
		"                         Low_path over_high_ms value\n");
	fprintf(stderr,
		"                         (default: 0)\n");
	fprintf(stderr, "  -L, --use_below_low    Enable use_below_low flag\n");
	fprintf(stderr, "  -M, --use_below_min    Enable use_below_min flag\n");
	fprintf(stderr,
		"  -O, --allow_override   Enable BPF_F_ALLOW_OVERRIDE\n");
	fprintf(stderr,
		"                         flag\n");
	fprintf(stderr, "  -h, --help             Show this help message\n\n");
	fprintf(stderr, "Examples:\n");
	fprintf(stderr, "  # Using long options:\n");
	fprintf(stderr, "  %s --low_path=/sys/fs/cgroup/low \\\n", name);
	fprintf(stderr, "     --high_path=/sys/fs/cgroup/high \\\n");
	fprintf(stderr, "     --threshold=1000 --over_high_ms=500 \\\n"
			"     --use_below_low\n\n");
	fprintf(stderr, "  # Using short options:\n");
	fprintf(stderr, "  %s -l /sys/fs/cgroup/low \\\n"
			"     -g /sys/fs/cgroup/high \\\n",
		name);
	fprintf(stderr, "     -t 1000 -o 500 -L -M\n");
}

static uint64_t get_cgroup_id(const char *cgroup_path)
{
	struct stat st;

	if (cgroup_path == NULL) {
		fprintf(stderr, "Error: cgroup_path is NULL\n");
		return 0;
	}

	if (stat(cgroup_path, &st) < 0) {
		fprintf(stderr, "Error: stat(%s) failed: %d\n",
			cgroup_path, errno);
		return 0;
	}

	return (uint64_t)st.st_ino;
}

int main(int argc, char **argv)
{
	int low_cgroup_fd = -1, high_cgroup_fd = -1;
	uint64_t threshold = 0, high_cgroup_id;
	unsigned int over_high_ms = 0;
	bool use_below_low = false, use_below_min = false;
	__u32 opts_flags = 0;
	const char *low_path = NULL;
	const char *high_path = NULL;
	const char *bpf_obj_file = "memcg.bpf.o";
	struct bpf_object *obj = NULL;
	struct bpf_program *prog = NULL;
	struct bpf_link *link = NULL, *link_low = NULL, *link_high = NULL;
	struct bpf_map *map;
	struct memcg__bss *bss_data;
	DECLARE_LIBBPF_OPTS(bpf_struct_ops_opts, opts);
	int err = -EINVAL;
	int map_fd;
	int opt;
	int option_index = 0;

	static struct option long_options[] = {
		{"low_path",       required_argument, 0, 'l'},
		{"high_path",      required_argument, 0, 'g'},
		{"threshold",      required_argument, 0, 't'},
		{"over_high_ms",   required_argument, 0, 'o'},
		{"use_below_low",  no_argument,       0, 'L'},
		{"use_below_min",  no_argument,       0, 'M'},
		{"allow_override", no_argument,       0, 'O'},
		{"help",           no_argument,       0, 'h'},
		{0,                0,                 0,  0 }
	};

	while ((opt = getopt_long(argc, argv, "l:g:t:o:LMOh",
				  long_options, &option_index)) != -1) {
		switch (opt) {
		case 'l':
			low_path = optarg;
			break;
		case 'g':
			high_path = optarg;
			break;
		case 't':
			threshold = strtoull(optarg, NULL, 10);
			break;
		case 'o':
			over_high_ms = strtoull(optarg, NULL, 10);
			break;
		case 'L':
			use_below_low = true;
			break;
		case 'M':
			use_below_min = true;
			break;
		case 'O':
			opts_flags = BPF_F_ALLOW_OVERRIDE;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return -EINVAL;
		}
	}

	if (!low_path || !high_path || !threshold) {
		fprintf(stderr,
			"ERROR: Missing required arguments\n\n");
		usage(argv[0]);
		goto out;
	}

	low_cgroup_fd = open(low_path, O_RDONLY);
	if (low_cgroup_fd < 0) {
		fprintf(stderr,
			"ERROR: open low cgroup '%s' failed: %d\n",
			low_path, errno);
		err = -errno;
		goto out;
	}

	high_cgroup_id = get_cgroup_id(high_path);
	if (!high_cgroup_id)
		goto out;
	high_cgroup_fd = open(high_path, O_RDONLY);
	if (high_cgroup_fd < 0) {
		fprintf(stderr,
			"ERROR: open high cgroup '%s' failed: %d\n",
			low_path, errno);
		err = -errno;
		goto out;
	}

	obj = bpf_object__open_file(bpf_obj_file, NULL);
	err = libbpf_get_error(obj);
	if (err) {
		fprintf(stderr,
			"ERROR: opening BPF object file '%s' failed: %d\n",
			bpf_obj_file, err);
		goto out;
	}

	map = bpf_object__find_map_by_name(obj, ".bss");
	if (!map) {
		fprintf(stderr, "ERROR: Failed to find .data map\n");
		err = -ESRCH;
		goto out;
	}

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr,
			"ERROR: loading BPF object file failed: %d\n",
			err);
		goto out;
	}

	map_fd = bpf_map__fd(map);
	bss_data = malloc(bpf_map__value_size(map));
	if (bss_data) {
		__u32 key = 0;

		memset(bss_data, 0, sizeof(struct local_config));
		bss_data->local_config.high_cgroup_id = high_cgroup_id;
		bss_data->local_config.threshold = threshold;
		bss_data->local_config.over_high_ms = over_high_ms;
		bss_data->local_config.use_below_low = use_below_low;
		bss_data->local_config.use_below_min = use_below_min;

		err = bpf_map_update_elem(map_fd, &key, bss_data, BPF_EXIST);
		free(bss_data);
		if (err) {
			fprintf(stderr,
				"ERROR: update config failed: %d\n",
				err);
			goto out;
		}
	} else {
		fprintf(stderr,
			"ERROR: allocate memory failed\n");
		err = -ENOMEM;
		goto out;
	}

	prog = bpf_object__find_program_by_name(obj,
						"handle_count_memcg_events");
	if (!prog) {
		fprintf(stderr,
			"ERROR: finding a prog in BPF object file failed\n");
		goto out;
	}

	link = bpf_program__attach(prog);
	err = libbpf_get_error(link);
	if (err) {
		fprintf(stderr,
			"ERROR: bpf_program__attach failed: %d\n",
			err);
		goto out;
	}

	if (over_high_ms) {
		map = bpf_object__find_map_by_name(obj, "low_mcg_ops");
		if (!map) {
			fprintf(stderr,
				"ERROR: Failed to find low_mcg_ops map\n");
			err = -ESRCH;
			goto out;
		}
		LIBBPF_OPTS_RESET(opts,
			.flags = opts_flags,
			.relative_fd = low_cgroup_fd,
		);
		link_low = bpf_map__attach_struct_ops_opts(map, &opts);
		if (!link_low) {
			fprintf(stderr,
				"Failed to attach struct ops low_mcg_ops: %d\n",
				errno);
			err = -errno;
			goto out;
		}
	}

	if (use_below_low || use_below_min) {
		map = bpf_object__find_map_by_name(obj, "high_mcg_ops");
		if (!map) {
			fprintf(stderr,
				"ERROR: Failed to find high_mcg_ops map\n");
			err = -ESRCH;
			goto out;
		}
		LIBBPF_OPTS_RESET(opts,
			.flags = opts_flags,
			.relative_fd = high_cgroup_fd,
		);
		link_low = bpf_map__attach_struct_ops_opts(map, &opts);
		if (!link_low) {
			fprintf(stderr,
				"Failed to attach struct ops high_mcg_ops: %d\n",
				errno);
			err = -errno;
			goto out;
		}
	}

	printf("Successfully attached!\n");

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	while (!exiting)
		pause();

	printf("Exiting...\n");

out:
	bpf_link__destroy(link);
	bpf_link__destroy(link_low);
	bpf_link__destroy(link_high);
	bpf_object__close(obj);
	close(low_cgroup_fd);
	close(high_cgroup_fd);
	return err;
}
