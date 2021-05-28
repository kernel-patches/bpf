// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2017 Jesper Dangaard Brouer, Red Hat, Inc.
 */
static const char *__doc__ =
	" XDP redirect with a CPU-map type \"BPF_MAP_TYPE_CPUMAP\"";

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <locale.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <getopt.h>
#include <net/if.h>
#include <time.h>
#include <linux/limits.h>

#include <arpa/inet.h>
#include <linux/if_link.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "bpf_util.h"
#include "xdp_sample_user.h"

static int ifindex = -1;
static char ifname_buf[IF_NAMESIZE];
static char *ifname;
static __u32 prog_id;
static int map_fd;
static int avail_fd;
static int count_fd;

static __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
static int mask = SAMPLE_RX_CNT | SAMPLE_REDIRECT_ERR_CNT |
		  SAMPLE_CPUMAP_ENQUEUE_CNT | SAMPLE_CPUMAP_KTHREAD_CNT |
		  SAMPLE_EXCEPTION_CNT;

static const struct option long_options[] = {
	{"help",	no_argument,		NULL, 'h' },
	{"dev",		required_argument,	NULL, 'd' },
	{"skb-mode",	no_argument,		NULL, 'S' },
	{"progname",	required_argument,	NULL, 'p' },
	{"qsize",	required_argument,	NULL, 'q' },
	{"cpu",		required_argument,	NULL, 'c' },
	{"stress-mode", no_argument,		NULL, 'x' },
	{"force",	no_argument,		NULL, 'F' },
	{"mprog-disable", no_argument,		NULL, 'n' },
	{"mprog-name",	required_argument,	NULL, 'e' },
	{"mprog-filename", required_argument,	NULL, 'f' },
	{"redirect-device", required_argument,	NULL, 'r' },
	{"redirect-map", required_argument,	NULL, 'm' },
	{"interval", required_argument,		NULL, 'i' },
	{"verbose", no_argument,		NULL, 'v' },
	{"stats", no_argument,			NULL, 's' },
	{}
};

static void int_exit(int sig)
{
	__u32 curr_prog_id = 0;

	if (ifindex > -1) {
		if (bpf_get_link_xdp_id(ifindex, &curr_prog_id, xdp_flags)) {
			printf("bpf_get_link_xdp_id failed\n");
			exit(EXIT_FAIL);
		}
		if (prog_id == curr_prog_id) {
			fprintf(stderr,
				"Interrupted: Removing XDP program on ifindex:%d device:%s\n",
				ifindex, ifname);
			bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
		} else if (!curr_prog_id) {
			printf("couldn't find a prog id on a given iface\n");
		} else {
			printf("program on interface changed, not removing\n");
		}
	}

	sample_exit(EXIT_OK);
}

static void print_avail_progs(struct bpf_object *obj)
{
	struct bpf_program *pos;

	bpf_object__for_each_program(pos, obj) {
		if (bpf_program__is_xdp(pos))
			printf(" %s\n", bpf_program__section_name(pos));
	}
}

static void usage(char *argv[], struct bpf_object *obj)
{
	int i;

	sample_print_help(mask);

	printf("\nDOCUMENTATION:\n%s\n", __doc__);
	printf("\n");
	printf(" Usage: %s (options-see-below)\n", argv[0]);
	printf(" Listing options:\n");
	for (i = 0; long_options[i].name != 0; i++) {
		printf(" --%-12s", long_options[i].name);
		if (long_options[i].flag != NULL)
			printf(" flag (internal value:%d)",
				*long_options[i].flag);
		else
			printf(" short-option: -%c",
				long_options[i].val);
		printf("\n");
	}
	printf("\n Programs to be used for --progname:\n");
	print_avail_progs(obj);
	printf("\n");
}

static int create_cpu_entry(__u32 cpu, struct bpf_cpumap_val *value,
			    __u32 avail_idx, bool new)
{
	__u32 curr_cpus_count = 0;
	__u32 key = 0;
	int ret;

	/* Update to bpf_skel */
	/* Add a CPU entry to cpumap, as this allocate a cpu entry in
	 * the kernel for the cpu.
	 */
	ret = bpf_map_update_elem(map_fd, &cpu, value, 0);
	if (ret) {
		fprintf(stderr, "Create CPU entry failed (err:%d)\n", ret);
		exit(EXIT_FAIL_BPF);
	}

	/* Inform bpf_prog's that a new CPU is available to select
	 * from via some control maps.
	 */
	ret = bpf_map_update_elem(avail_fd, &avail_idx, &cpu, 0);
	if (ret) {
		fprintf(stderr, "Add to avail CPUs failed\n");
		exit(EXIT_FAIL_BPF);
	}

	/* When not replacing/updating existing entry, bump the count */
	ret = bpf_map_lookup_elem(count_fd, &key, &curr_cpus_count);
	if (ret) {
		fprintf(stderr, "Failed reading curr cpus_count\n");
		exit(EXIT_FAIL_BPF);
	}
	if (new) {
		curr_cpus_count++;
		ret = bpf_map_update_elem(count_fd, &key,
					  &curr_cpus_count, 0);
		if (ret) {
			fprintf(stderr, "Failed write curr cpus_count\n");
			exit(EXIT_FAIL_BPF);
		}
	}
	/* map_fd[7] = cpus_iterator */
	printf("%s CPU:%u as idx:%u qsize:%d prog_fd: %d (cpus_count:%u)\n",
	       new ? "Add-new":"Replace", cpu, avail_idx,
	       value->qsize, value->bpf_prog.fd, curr_cpus_count);

	return 0;
}

/* CPUs are zero-indexed. Thus, add a special sentinel default value
 * in map cpus_available to mark CPU index'es not configured
 */
static void mark_cpus_unavailable(void)
{
	__u32 invalid_cpu = n_cpus;
	int ret, i;

	for (i = 0; i < n_cpus; i++) {
		ret = bpf_map_update_elem(avail_fd, &i,
					  &invalid_cpu, 0);
		if (ret) {
			fprintf(stderr, "Failed marking CPU unavailable\n");
			exit(EXIT_FAIL_BPF);
		}
	}
}

/* Stress cpumap management code by concurrently changing underlying cpumap */
static void stress_cpumap(struct bpf_cpumap_val *value)
{
	/* Changing qsize will cause kernel to free and alloc a new
	 * bpf_cpu_map_entry, with an associated/complicated tear-down
	 * procedure.
	 */
	value->qsize = 1024;
	create_cpu_entry(1, value, 0, false);
	value->qsize = 8;
	create_cpu_entry(1, value, 0, false);
	value->qsize = 16000;
	create_cpu_entry(1, value, 0, false);
}

static void __stats_poll(int interval, bool redir_suc, char *prog_name,
			 char *mprog_name, struct bpf_cpumap_val *value,
			 bool stress_mode)
{
	struct stats_record *record, *prev;

	record = alloc_stats_record();
	prev   = alloc_stats_record();
	sample_stats_collect(mask, record);

	/* Trick to pretty printf with thousands separators use %' */
	setlocale(LC_NUMERIC, "en_US");

	if (redir_suc)
		mask |= SAMPLE_REDIRECT_CNT;

	for (;;) {
		struct timespec ots, nts;

		clock_gettime(CLOCK_MONOTONIC, &ots);
		swap(&prev, &record);
		sample_stats_collect(mask, record);
		sample_stats_print(mask, record, prev, NULL, interval);
		/* Depends on SAMPLE_CPUMAP_KTHREAD_CNT */
		sample_stats_print_cpumap_remote(record, prev,
						 bpf_num_possible_cpus(),
						 mprog_name);
		if (sample_log_level & LL_DEFAULT)
			printf("\n");
		fflush(stdout);
		clock_gettime(CLOCK_MONOTONIC, &nts);
		sample_calc_timediff(&nts, &ots, interval);
		nanosleep(&nts, NULL);
		if (stress_mode)
			stress_cpumap(value);
		sample_reset_mode();
	}

	free_stats_record(record);
	free_stats_record(prev);
}

static int load_cpumap_prog(char *file_name, char *prog_name,
			    char *redir_interface, char *redir_map)
{
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type		= BPF_PROG_TYPE_XDP,
		.expected_attach_type	= BPF_XDP_CPUMAP,
		.file = file_name,
	};
	struct bpf_program *prog;
	struct bpf_object *obj;
	int fd;

	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &fd))
		return -1;

	if (fd < 0) {
		fprintf(stderr, "ERR: bpf_prog_load_xattr: %s\n",
			strerror(errno));
		return fd;
	}

	if (redir_interface && redir_map) {
		int err, map_fd, ifindex_out, key = 0;

		map_fd = bpf_object__find_map_fd_by_name(obj, redir_map);
		if (map_fd < 0)
			return map_fd;

		ifindex_out = if_nametoindex(redir_interface);
		if (!ifindex_out)
			return -1;

		err = bpf_map_update_elem(map_fd, &key, &ifindex_out, 0);
		if (err < 0)
			return err;
	}

	prog = bpf_object__find_program_by_title(obj, prog_name);
	if (!prog) {
		fprintf(stderr, "bpf_object__find_program_by_title failed\n");
		return EXIT_FAIL;
	}

	return bpf_program__fd(prog);
}

int main(int argc, char **argv)
{
	char *prog_name = "xdp_cpu_map5_lb_hash_ip_pairs";
	char *mprog_filename = "xdp_redirect_kern.o";
	char *redir_interface = NULL, *redir_map = NULL;
	char *mprog_name = "xdp_redirect_dummy";
	bool mprog_disable = false;
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type	= BPF_PROG_TYPE_UNSPEC,
	};
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	struct bpf_cpumap_val value;
	bool stress_mode = false;
	struct bpf_program *prog;
	struct bpf_object *obj;
	int err = EXIT_FAIL;
	char filename[256];
	bool redir = false;
	int added_cpus = 0;
	int longindex = 0;
	int interval = 2;
	int add_cpu = -1;
	int opt, prog_fd;
	int *cpu, i;
	__u32 qsize;

	/* Notice: choosing he queue size is very important with the
	 * ixgbe driver, because it's driver page recycling trick is
	 * dependend on pages being returned quickly.  The number of
	 * out-standing packets in the system must be less-than 2x
	 * RX-ring size.
	 */
	qsize = 128+64;

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	prog_load_attr.file = filename;

	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd))
		return err;

	if (prog_fd < 0) {
		fprintf(stderr, "ERR: bpf_prog_load_xattr: %s\n",
			strerror(errno));
		return err;
	}

	if (sample_init(obj) < 0) {
		fprintf(stderr, "ERR: Failed to initialize sample\n");
		return err;
	}

	map_fd = bpf_object__find_map_fd_by_name(obj, "cpu_map");
	avail_fd = bpf_object__find_map_fd_by_name(obj, "cpus_available");
	count_fd = bpf_object__find_map_fd_by_name(obj, "cpus_count");

	if (map_fd < 0 || avail_fd < 0 || count_fd < 0) {
		fprintf(stderr, "failed to find map\n");
		return EXIT_FAIL;
	}

	mark_cpus_unavailable();

	cpu = malloc(n_cpus * sizeof(int));
	if (!cpu) {
		fprintf(stderr, "failed to allocate cpu array\n");
		return err;
	}
	memset(cpu, 0, n_cpus * sizeof(int));

	/* Parse commands line args */
	while ((opt = getopt_long(argc, argv, "hSd:sp:q:c:xi:vFf:e:r:m:",
				  long_options, &longindex)) != -1) {
		switch (opt) {
		case 'd':
			if (strlen(optarg) >= IF_NAMESIZE) {
				fprintf(stderr, "ERR: --dev name too long\n");
				goto error;
			}
			ifname = (char *)&ifname_buf;
			strncpy(ifname, optarg, IF_NAMESIZE);
			ifindex = if_nametoindex(ifname);
			if (ifindex == 0) {
				fprintf(stderr,
					"ERR: --dev name unknown err(%d):%s\n",
					errno, strerror(errno));
				goto error;
			}
			break;
		case 's':
			redir = true;
			break;
		case 'i':
			interval = atoi(optarg);
			break;
		case 'S':
			xdp_flags |= XDP_FLAGS_SKB_MODE;
			break;
		case 'x':
			stress_mode = true;
			break;
		case 'p':
			/* Selecting eBPF prog to load */
			prog_name = optarg;
			break;
		case 'n':
			mprog_disable = true;
			break;
		case 'f':
			mprog_filename = optarg;
			break;
		case 'e':
			mprog_name = optarg;
			break;
		case 'r':
			redir_interface = optarg;
			break;
		case 'm':
			redir_map = optarg;
			break;
		case 'c':
			/* Add multiple CPUs */
			add_cpu = strtoul(optarg, NULL, 0);
			if (add_cpu >= n_cpus) {
				fprintf(stderr,
				"--cpu nr too large for cpumap err(%d):%s\n",
					errno, strerror(errno));
				goto error;
			}
			cpu[added_cpus++] = add_cpu;
			break;
		case 'q':
			qsize = atoi(optarg);
			break;
		case 'F':
			xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
			break;
		case 'v':
			sample_log_level ^= LL_DEBUG - 1;
			break;
		case 'h':
		error:
		default:
			free(cpu);
			usage(argv, obj);
			return EXIT_FAIL_OPTION;
		}
	}

	if (!(xdp_flags & XDP_FLAGS_SKB_MODE))
		xdp_flags |= XDP_FLAGS_DRV_MODE;

	/* Required option */
	if (ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n");
		usage(argv, obj);
		err = EXIT_FAIL_OPTION;
		goto out;
	}
	/* Required option */
	if (add_cpu == -1) {
		fprintf(stderr, "ERR: required option --cpu missing\n");
		fprintf(stderr, " Specify multiple --cpu option to add more\n");
		usage(argv, obj);
		err = EXIT_FAIL_OPTION;
		goto out;
	}

	value.bpf_prog.fd = 0;
	if (!mprog_disable)
		value.bpf_prog.fd = load_cpumap_prog(mprog_filename, mprog_name,
						     redir_interface, redir_map);
	if (value.bpf_prog.fd < 0) {
		err = value.bpf_prog.fd;
		goto out;
	}
	value.qsize = qsize;

	for (i = 0; i < added_cpus; i++)
		create_cpu_entry(cpu[i], &value, i, true);

	/* Remove XDP program when program is interrupted or killed */
	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);

	prog = bpf_object__find_program_by_title(obj, prog_name);
	if (!prog) {
		fprintf(stderr, "bpf_object__find_program_by_title failed\n");
		goto out;
	}

	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0) {
		fprintf(stderr, "bpf_program__fd failed\n");
		goto out;
	}

	if (bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags) < 0) {
		fprintf(stderr, "link set xdp fd failed\n");
		err = EXIT_FAIL_XDP;
		goto out;
	}

	err = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
	if (err) {
		printf("can't get prog info - %s\n", strerror(errno));
		goto out;
	}
	prog_id = info.id;

	if (!redir) {
		/* The bpf_link[i] depend on the order of
		 * the functions was defined in _kern.c
		 */
		bpf_link__destroy(tp_links[2]);	/* tracepoint/xdp/xdp_redirect */
		tp_links[2] = NULL;

		bpf_link__destroy(tp_links[3]);	/* tracepoint/xdp/xdp_redirect_map */
		tp_links[3] = NULL;
	}

	__stats_poll(interval, redir, prog_name, mprog_name,
		     &value, stress_mode);

	err = EXIT_OK;
out:
	free(cpu);
	return err;
}
