// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <stdbool.h>
#include <getopt.h>
#include <sys/epoll.h>
#include <linux/limits.h>
#include <sys/stat.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "mthp_ext.h"
#include "mthp_ext.skel.h"

#define DEFAULT_ROOT		"/sys/fs/cgroup"
#define DEFAULT_THRESHOLD_MS	100UL
#define DEFAULT_INTERVAL_MS	1000UL
#define DEFAULT_ORDER		PMD_ORDER
#define DEFAULT_MIN_MEM		16

static bool exiting;

static void usage(const char *name)
{
	fprintf(stderr,
		"Usage: %s [OPTIONS]\n\n"
		"Monitor specified cgroup, adjust mTHP size via cgroup_bpf.\n\n"
		"Currently supports fixed mTHP size and automatic mTHP size adjustment.\n"
		"By default, it monitors the entire cgroup and automatically\n"
		"adjusts mTHP size within the specified time window <interval>.\n"
		"1. When the memory size of the sub-cgroup falls below\n"
		"   the <min> threshold, it will automatically fall back to\n"
		"   using 4KB size; otherwise, it will use all mTHP sizes.\n"
		"2. When memory.pressure stall time of the sub-cgroup exceeds\n"
		"   <threshold>, it will automatically fall back to using 4KB\n"
		"   size; otherwise, it will use all mTHP sizes.\n\n"
		"Options:\n"
		"  -r, --root=PATH        Root cgroup path (default: /sys/fs/cgroup)\n"
		"  -t, --threshold=MS     threshold in ms (default: %lu)\n"
		"  -i, --interval=MS      interval in ms (default: %lu)\n"
		"  -o, --order=NR         Initial mthp order (default: %d)\n"
		"  -m, --min=MB           Minimum memory size for mTHP (default: %d)\n"
		"  -f, --fixed            Use fixed order, disable auto-adjustment\n"
		"  -d, --debug            Enable debug output\n"
		"  -h, --help             Show this help\n",
		name, DEFAULT_THRESHOLD_MS, DEFAULT_INTERVAL_MS, DEFAULT_ORDER,
		DEFAULT_MIN_MEM);
}

static void sig_handler(int sig)
{
	exiting = true;
}

static int setup_psi_trigger(const char *cgroup_path, const char *type,
			     unsigned long stall_us, unsigned long window_us)
{
	char path[PATH_MAX];
	char trigger[128];
	int fd, nr;

	snprintf(path, sizeof(path), "%s/memory.pressure", cgroup_path);
	fd = open(path, O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		fprintf(stderr, "ERROR: open PSI file failed\n");
		return -errno;
	}

	nr = snprintf(trigger, sizeof(trigger), "%s %lu %lu",
		      type, stall_us, window_us);
	if (write(fd, trigger, nr) < 0) {
		fprintf(stderr, "ERROR: write PSI trigger failed\n");
		close(fd);
		return -errno;
	}

	return fd;
}

static int trigger_scan(struct bpf_link *iter_link)
{
	char buf[256];
	int fd;

	fd = bpf_iter_create(bpf_link__fd(iter_link));
	if (fd < 0) {
		fprintf(stderr, "ERROR: bpf_iter_create failed: %s\n",
			strerror(errno));
		return -1;
	}

	/* Read to trigger the iter program execution */
	while (read(fd, buf, sizeof(buf)))
		;

	close(fd);
	return 0;
}

static void *monitor_thread(int psi_fd, struct config_local *configs,
		struct bpf_link *iter_link, struct ring_buffer *rb)
{
	struct epoll_event e;
	int epoll_fd;
	int nfds;

	epoll_fd = epoll_create1(0);
	if (epoll_fd < 0) {
		fprintf(stderr, "ERROR: epoll_create1 failed\n");
		return NULL;
	}

	e.events = EPOLLPRI;
	e.data.fd = psi_fd;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, psi_fd, &e)) {
		fprintf(stderr, "ERROR: epoll_ctl failed\n");
		goto CLOSE;
	}

	/* First initialization */
	trigger_scan(iter_link);
	if (configs->debug)
		ring_buffer__poll(rb, 0);

	/* Auto adjustment */
	while (!exiting) {
		nfds = epoll_wait(epoll_fd, &e, 1, configs->interval);
		trigger_scan(iter_link);

		if (configs->debug) {
			printf("PSI: memory pressure %s\n", nfds ? "high" : "low");
			ring_buffer__poll(rb, 0);
		}
	}

CLOSE:
	close(epoll_fd);
	return NULL;
}

static int handle_event(void *ctx, void *data, size_t len)
{
	struct alert_event *e = data;

	printf("cgroup %s: stall %lu -> %lu (+%lu), mem %luMB, mthp order=%d\n",
		e->name[0] ? e->name : "/",
		e->prev_stall, e->curr_stall, e->delta, TO_MB(e->mem), e->order);

	return 0;
}

int main(int argc, char **argv)
{
	const char *root_path = DEFAULT_ROOT;
	unsigned long threshold = DEFAULT_THRESHOLD_MS;
	unsigned long interval = DEFAULT_INTERVAL_MS;
	unsigned int init_order = DEFAULT_ORDER;
	unsigned int min_mem = DEFAULT_MIN_MEM;
	bool fixed = false;
	bool debug = false;
	struct mthp_ext *skel;
	struct bpf_link *iter_link;
	struct bpf_link *ops_link;
	struct ring_buffer *rb;
	int root_fd;
	int psi_fd;
	int err = 0;
	int opt;

	static struct option long_options[] = {
		{"root",       required_argument, 0, 'r'},
		{"threshold",  required_argument, 0, 't'},
		{"interval",   required_argument, 0, 'i'},
		{"order",      required_argument, 0, 'o'},
		{"min",        required_argument, 0, 'm'},
		{"fixed",      no_argument,       0, 'f'},
		{"debug",      no_argument,       0, 'd'},
		{"help",       no_argument,       0, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "r:t:i:o:m:fdh",
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 'r':
			root_path = optarg;
			break;
		case 't':
			threshold = strtoul(optarg, NULL, 10);
			break;
		case 'i':
			interval = strtoul(optarg, NULL, 10);
			break;
		case 'o':
			init_order = min(strtoul(optarg, NULL, 10), PMD_ORDER);
			break;
		case 'm':
			min_mem = strtoul(optarg, NULL, 10);
			break;
		case 'f':
			fixed = true;
			break;
		case 'd':
			debug = true;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return -EINVAL;
		}
	}

	if (!threshold || !interval) {
		fprintf(stderr, "ERROR: threshold and interval must be > 0\n");
		usage(argv[0]);
		return -EINVAL;
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	root_fd = open(root_path, O_RDONLY);
	if (root_fd < 0) {
		fprintf(stderr, "ERROR: open '%s' failed: %s\n",
			root_path, strerror(errno));
		return -errno;
	}

	skel = mthp_ext__open();
	if (!skel) {
		fprintf(stderr, "ERROR: failed to open BPF skeleton\n");
		err = -ENOMEM;
		goto open_skel_fail;
	}

	skel->bss->configs.threshold = threshold;
	skel->bss->configs.interval = interval;
	skel->bss->configs.init_order = init_order;
	skel->bss->configs.min_mem = min_mem;
	skel->bss->configs.fixed = fixed;
	skel->bss->configs.debug = debug;

	err = mthp_ext__load(skel);
	if (err) {
		fprintf(stderr, "ERROR: failed to load BPF program: %d\n", err);
		goto load_skel_fail;
	}

	/* Attach struct_ops to root cgroup for mthp_choose */
	DECLARE_LIBBPF_OPTS(bpf_struct_ops_opts, opts);
	opts.flags = BPF_F_CGROUP_FD;
	opts.target_fd = root_fd;
	ops_link = bpf_map__attach_struct_ops_opts(skel->maps.mthp_ops, &opts);
	err = libbpf_get_error(ops_link);
	if (err) {
		fprintf(stderr, "ERROR: attach struct_ops failed: %d\n", err);
		ops_link = NULL;
		goto attach_opts_fail;
	}

	printf("Monitoring         : %s\n"
	       "threshold          : %lums\n"
	       "Interval           : %lums\n"
	       "Initial order      : %d%s\n"
	       "min memory         : %dMB\n"
	       "Debug              : %s\n"
	       "Press Ctrl+C to exit.\n\n",
	       root_path, threshold, interval, init_order,
	       fixed ? " (fixed)" : " (auto)", min_mem,
	       debug ? "on" : "off");

	if (fixed) {
		while (!exiting)
			usleep(interval * 1000);
		goto exit_fixed;
	}

	/* Auto adjustment, attach cgroup iter for scanning root + descendants */
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, iter_opts);
	union bpf_iter_link_info linfo = {
		.cgroup.cgroup_fd = root_fd,
		.cgroup.order = BPF_CGROUP_ITER_DESCENDANTS_PRE,
	};
	iter_opts.link_info = &linfo;
	iter_opts.link_info_len = sizeof(linfo);
	iter_link = bpf_program__attach_iter(skel->progs.cgroup_scan, &iter_opts);
	err = libbpf_get_error(iter_link);
	if (err) {
		fprintf(stderr, "ERROR: attach cgroup iter failed: %d\n", err);
		iter_link = NULL;
		goto attach_iter_fail;
	}

	/* Set up ring buffer for receiving alerts */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
			      handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "ERROR: failed to create ring buffer\n");
		err = -ENOMEM;
		goto rb_fail;
	}


	psi_fd = setup_psi_trigger(root_path, "some", threshold * 1000,
				   interval * 1000);
	if (psi_fd < 0) {
		fprintf(stderr, "ERROR: PSI trigger setup failed\n");
		goto psi_setup_fail;
	}

	monitor_thread(psi_fd, &skel->bss->configs, iter_link, rb);

	close(psi_fd);
psi_setup_fail:
	ring_buffer__free(rb);
rb_fail:
	bpf_link__destroy(iter_link);
exit_fixed:
attach_iter_fail:
	bpf_link__destroy(ops_link);
attach_opts_fail:
load_skel_fail:
	mthp_ext__destroy(skel);
open_skel_fail:
	close(root_fd);

	printf("\nExiting...\n");

	return err;
}
