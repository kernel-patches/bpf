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
#include <signal.h>
#include <stdbool.h>
#include <getopt.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#ifndef __MEMCG_RSTAT_SIMPLE_BPF_SKEL_H__
#define u64 uint64_t
#endif

struct local_config {
	u64		threshold;
	u64		high_cgroup_id;
	u64		low_cgroup_id;
	bool		use_below_low;
	bool		use_below_min;
	unsigned int	over_high_ms;
	u64		async_trigger_bytes;
};

#include "memcg.skel.h"

static bool exiting;

static void sig_handler(int sig)
{
	exiting = true;
}

static void usage(const char *name)
{
	fprintf(stderr,
		"Usage: %s --low_path=<path> --high_path=<path>\n"
		"          --threshold=<value> [OPTIONS]\n\n",
		name);

	fprintf(stderr, "Required arguments:\n");
	fprintf(stderr,
		"  -l, --low_path=PATH      Low priority memcgroup path\n");
	fprintf(stderr,
		"  -g, --high_path=PATH     High priority memcgroup path\n");
	fprintf(stderr,
		"  -t, --threshold=VALUE    Sum of PGFAULT 'val' events from\n"
		"                           the high-priority cgroup per second\n"
		"                           needed to trigger low-priority\n"
		"                           cgroup throttling\n\n");

	fprintf(stderr, "Priority throttling options:\n");
	fprintf(stderr,
		"  -L, --use_below_low      Enable the below_low hook on the\n"
		"                           high-priority cgroup\n");
	fprintf(stderr,
		"  -M, --use_below_min      Enable the below_min hook on the\n"
		"                           high-priority cgroup\n");
	fprintf(stderr,
		"  -o, --over_high_ms=VALUE Delay (ms) returned by memcg_charged\n"
		"                           for the low-priority cgroup while\n"
		"                           throttling is active (default: 0)\n");
	fprintf(stderr,
		"  -a, --async_trigger_bytes=BYTES\n"
		"                           Memory threshold bytes for\n"
		"                           the async-reclaim Low priority\n"
		"                           memcgroup above which background\n"
		"                           page reclaim is triggered.\n"
		"                           0 or omitted = feature disabled.\n");
	fprintf(stderr,
		"  -O, --allow_override     Set BPF_F_ALLOW_OVERRIDE when\n"
		"                           attaching struct_ops\n\n");

	fprintf(stderr, "Misc:\n");
	fprintf(stderr, "  -h, --help              Show this help message\n\n");

	fprintf(stderr, "Examples:\n");
	fprintf(stderr,
		"  # Priority throttling only:\n"
		"  %s --low_path=/sys/fs/cgroup/low \\\n"
		"     --high_path=/sys/fs/cgroup/high \\\n"
		"     --threshold=1000 --over_high_ms=500 --use_below_low\n\n",
		name);
	fprintf(stderr,
		"  # Async reclaim only (no throttling):\n"
		"  %s --low_path=/sys/fs/cgroup/low \\\n"
		"     --threshold=1000 \\\n"
		"     --async_trigger_bytes=33554432\n\n",
		name);
	fprintf(stderr,
		"  # Both features combined:\n"
		"  %s --low_path=/sys/fs/cgroup/low \\\n"
		"     --high_path=/sys/fs/cgroup/high \\\n"
		"     --threshold=1000 --over_high_ms=500 \\\n"
		"     --async_trigger_bytes=33554432\n",
		name);
}

static uint64_t get_cgroup_id(const char *cgroup_path)
{
	struct stat st;

	if (!cgroup_path) {
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

static uint64_t parse_u64(const char *str, const char *prog)
{
	uint64_t value;

	errno = 0;
	value = strtoull(str, NULL, 10);
	if (errno != 0) {
		fprintf(stderr, "ERROR: strtoull '%s' failed: %d\n",
			str, errno);
		usage(prog);
		exit(-errno);
	}
	return value;
}

static int
attach_ops(struct bpf_object *obj, __u32 opts_flags, const char *name, int fd,
	   struct bpf_link **link_ptr)
{
	int err;
	struct bpf_map *map;
	struct bpf_link *link;
	DECLARE_LIBBPF_OPTS(bpf_struct_ops_opts, opts,
		.flags    = opts_flags | BPF_F_CGROUP_FD,
		.target_fd = fd,
	);

	map = bpf_object__find_map_by_name(obj, name);
	if (!map) {
		fprintf(stderr,
			"ERROR: Failed to find %s map\n", name);
		err = -ESRCH;
		goto out;
	}
	link = bpf_map__attach_struct_ops_opts(map, &opts);
	err = libbpf_get_error(link);
	if (err) {
		link = NULL;
		fprintf(stderr,
			"Failed to attach struct ops %s: %d\n",
			name, err);
		goto out;
	}
	*link_ptr = link;

out:
	return err;
}

int main(int argc, char **argv)
{
	int low_cgroup_fd = -1, high_cgroup_fd = -1;
	struct local_config local_config = {
		.threshold = 1,
		.high_cgroup_id = 0,
		.low_cgroup_id = 0,
		.use_below_low = false,
		.use_below_min = false,
		.over_high_ms = 0,
		.async_trigger_bytes = 0,
	};
	LIBBPF_OPTS(bpf_test_run_opts, run_opts,
		.ctx_in = &local_config,
		.ctx_size_in = sizeof(local_config)
	);
	int prog_init_fd;
	__u32 opts_flags = 0;
	const char *low_path = NULL;
	const char *high_path = NULL;
	struct memcg *skel = NULL;
	struct bpf_program *prog = NULL;
	struct bpf_link *link = NULL, *link_low = NULL, *link_high = NULL;
	int err = -EINVAL;
	int opt;
	int option_index = 0;

	static struct option long_options[] = {
		/* required */
		{"low_path",		  required_argument, 0, 'l'},
		{"high_path",		  required_argument, 0, 'g'},
		{"threshold",		  required_argument, 0, 't'},
		/* priority throttling */
		{"over_high_ms",	  required_argument, 0, 'o'},
		{"use_below_low",	  no_argument,	     0, 'L'},
		{"use_below_min",	  no_argument,	     0, 'M'},
		{"async_trigger_bytes",	  required_argument, 0, 'a'},
		{"allow_override",	  no_argument,	     0, 'O'},
		/* misc */
		{"help",		  no_argument,	     0, 'h'},
		{0,			  0,		     0,	 0 }
	};

	while ((opt = getopt_long(argc, argv, "l:g:t:o:LMOa:h",
				  long_options, &option_index)) != -1) {
		switch (opt) {
		case 'l':
			low_path = optarg;
			break;
		case 'g':
			high_path = optarg;
			break;
		case 't':
			local_config.threshold = parse_u64(optarg, argv[0]);
			break;
		case 'o':
			local_config.over_high_ms
				= (unsigned int)parse_u64(optarg, argv[0]);
			break;
		case 'L':
			local_config.use_below_low = true;
			break;
		case 'M':
			local_config.use_below_min = true;
			break;
		case 'O':
			opts_flags = BPF_F_ALLOW_OVERRIDE;
			break;
		case 'a':
			local_config.async_trigger_bytes
				= parse_u64(optarg, argv[0]);
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return -EINVAL;
		}
	}

	if ((!local_config.use_below_low &&
	     !local_config.use_below_min &&
	     !local_config.async_trigger_bytes &&
	     !local_config.over_high_ms) ||
		((local_config.use_below_low || local_config.use_below_min) &&
	     !high_path) ||
	    (local_config.async_trigger_bytes && !low_path) ||
	    (local_config.over_high_ms && (!high_path || !low_path))) {
		fprintf(stderr, "ERROR: Missing required arguments\n\n");
		usage(argv[0]);
		goto out;
	}


	if (low_path) {
		low_cgroup_fd = open(low_path, O_RDONLY);
		if (low_cgroup_fd < 0) {
			fprintf(stderr,
				"ERROR: open low cgroup '%s' failed: %d\n",
				low_path, errno);
			err = -errno;
			goto out;
		}

		local_config.low_cgroup_id = get_cgroup_id(low_path);
		if (!local_config.low_cgroup_id) {
			fprintf(stderr,
				"ERROR: get low cgroup '%s' id failed: %d\n",
				low_path, errno);
			err = -errno;
			goto out;
		}
	}

	if (high_path) {
		high_cgroup_fd = open(high_path, O_RDONLY);
		if (high_cgroup_fd < 0) {
			fprintf(stderr,
				"ERROR: open high cgroup '%s' failed: %d\n",
				high_path, errno);
			err = -errno;
			goto out;
		}

		local_config.high_cgroup_id = get_cgroup_id(high_path);
		if (!local_config.high_cgroup_id) {
			fprintf(stderr,
				"ERROR: get high cgroup '%s' id failed: %d\n",
				high_path, errno);
			err = -errno;
			goto out;
		}
	}

	skel = memcg__open_and_load();
	if (!skel) {
		err = -errno;
		fprintf(stderr,
			"ERROR: opening and loading BPF skeleton failed: %d\n",
			err);
		goto out;
	}

	prog_init_fd = bpf_program__fd(skel->progs.prog_init);
	err = bpf_prog_test_run_opts(prog_init_fd, &run_opts);
	if (err || run_opts.retval) {
		fprintf(stderr,
			"ERROR: prog_init failed (err=%d retval=%d)\n",
			err, run_opts.retval);
		err = err ? err : -run_opts.retval;
		goto out;
	}

	if (local_config.use_below_low && local_config.use_below_min) {
		err = attach_ops(skel->obj, opts_flags, "high_mcg_ops",
				 high_cgroup_fd, &link_high);
		if (err)
			goto out;
	} else if (local_config.use_below_low) {
		err = attach_ops(skel->obj, opts_flags,
				 "high_mcg_ops_below_low",
				 high_cgroup_fd, &link_high);
		if (err)
			goto out;
	} else if (local_config.use_below_min) {
		err = attach_ops(skel->obj, opts_flags,
				 "high_mcg_ops_below_min",
				 high_cgroup_fd, &link_high);
		if (err)
			goto out;
	}

	if (local_config.over_high_ms && local_config.async_trigger_bytes) {
		err = attach_ops(skel->obj, opts_flags,
				 "low_mcg_ops",
				 low_cgroup_fd, &link_low);
		if (err)
			goto out;
	} else if (local_config.over_high_ms) {
		err = attach_ops(skel->obj, opts_flags,
				 "low_mcg_ops_high_delay",
				 low_cgroup_fd, &link_low);
		if (err)
			goto out;
	} else if (local_config.async_trigger_bytes) {
		err = attach_ops(skel->obj, opts_flags,
				 "low_mcg_ops_async",
				 low_cgroup_fd, &link_low);
		if (err)
			goto out;
	}

	if (local_config.use_below_low || local_config.use_below_min ||
	    local_config.over_high_ms) {
		prog = bpf_object__find_program_by_name(skel->obj,
						"handle_count_memcg_events");
		if (!prog) {
			fprintf(stderr,
			"ERROR: finding a prog in BPF object file failed\n");
			goto out;
		}

		link = bpf_program__attach(prog);
		err = libbpf_get_error(link);
		if (err) {
			link = NULL;
			fprintf(stderr,
				"ERROR: bpf_program__attach failed: %d\n",
				err);
			goto out;
		}
	}

	printf("Successfully attached!\n");

	signal(SIGINT,  sig_handler);
	signal(SIGTERM, sig_handler);

	while (!exiting)
		pause();

	printf("Exiting...\n");
	err = 0;

out:
	bpf_link__destroy(link);
	bpf_link__destroy(link_low);
	bpf_link__destroy(link_high);
	if (skel) {
		memcg__detach(skel);
		memcg__destroy(skel);
	}
	if (low_cgroup_fd >= 0)
		close(low_cgroup_fd);
	if (high_cgroup_fd >= 0)
		close(high_cgroup_fd);
	return err;
}
