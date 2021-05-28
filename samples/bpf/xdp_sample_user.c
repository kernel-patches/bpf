// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2017 Jesper Dangaard Brouer, Red Hat, Inc.
 */

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
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#ifndef SIOCETHTOOL
#define SIOCETHTOOL 0x8946
#endif

#include <arpa/inet.h>
#include <linux/if_link.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "bpf_util.h"
#include "xdp_sample_user.h"

struct bpf_link *tp_links[NUM_TP] = {};
int map_fds[NUM_MAP], tp_cnt, n_cpus;

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static __u64 gettime(void)
{
	struct timespec t;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &t);
	if (res < 0) {
		fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
		exit(EXIT_FAIL);
	}
	return (__u64) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

static bool map_collect_percpu(int fd, __u32 key, struct record *rec)
{
	/* For percpu maps, userspace gets a value per possible CPU */
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct datarec values[nr_cpus];
	__u64 sum_xdp_redirect = 0;
	__u64 sum_xdp_pass = 0;
	__u64 sum_xdp_drop = 0;
	__u64 sum_processed = 0;
	__u64 sum_dropped = 0;
	__u64 sum_issue = 0;
	int i;

	if ((bpf_map_lookup_elem(fd, &key, values)) != 0) {
		fprintf(stderr,
			"ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
		return false;
	}
	/* Get time as close as possible to reading map contents */
	rec->timestamp = gettime();

	/* Record and sum values from each CPU */
	for (i = 0; i < nr_cpus; i++) {
		rec->cpu[i].processed = values[i].processed;
		sum_processed        += values[i].processed;
		rec->cpu[i].dropped = values[i].dropped;
		sum_dropped        += values[i].dropped;
		rec->cpu[i].issue = values[i].issue;
		sum_issue        += values[i].issue;
		rec->cpu[i].xdp_pass = values[i].xdp_pass;
		sum_xdp_pass += values[i].xdp_pass;
		rec->cpu[i].xdp_drop = values[i].xdp_drop;
		sum_xdp_drop += values[i].xdp_drop;
		rec->cpu[i].xdp_redirect = values[i].xdp_redirect;
		sum_xdp_redirect += values[i].xdp_redirect;
	}
	rec->total.processed = sum_processed;
	rec->total.dropped   = sum_dropped;
	rec->total.issue     = sum_issue;
	rec->total.xdp_pass  = sum_xdp_pass;
	rec->total.xdp_drop  = sum_xdp_drop;
	rec->total.xdp_redirect = sum_xdp_redirect;
	return true;
}

static struct datarec *alloc_record_per_cpu(void)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct datarec *array;

	array = calloc(nr_cpus, sizeof(struct datarec));
	if (!array) {
		fprintf(stderr, "Mem alloc error (nr_cpus:%u)\n", nr_cpus);
		exit(EXIT_FAIL_MEM);
	}
	return array;
}

struct stats_record *alloc_stats_record(void)
{
	struct stats_record *rec;
	int i, size;

	size = sizeof(*rec) + n_cpus * sizeof(struct record);
	rec = malloc(size);
	if (!rec) {
		fprintf(stderr, "Mem alloc error\n");
		exit(EXIT_FAIL_MEM);
	}
	memset(rec, 0, size);
	rec->rx_cnt.cpu    = alloc_record_per_cpu();
	rec->redir_err[0].cpu = alloc_record_per_cpu();
	rec->redir_err[1].cpu = alloc_record_per_cpu();
	rec->kthread.cpu   = alloc_record_per_cpu();
	for (i = 0; i < XDP_ACTION_MAX; i++)
		rec->exception[i].cpu = alloc_record_per_cpu();
	rec->devmap_xmit.cpu = alloc_record_per_cpu();
	for (i = 0; i < n_cpus; i++)
		rec->enq[i].cpu = alloc_record_per_cpu();

	return rec;
}

void free_stats_record(struct stats_record *r)
{
	int i;

	for (i = 0; i < n_cpus; i++)
		free(r->enq[i].cpu);
	free(r->devmap_xmit.cpu);
	for (i = 0; i < XDP_ACTION_MAX; i++)
		free(r->exception[i].cpu);
	free(r->kthread.cpu);
	free(r->redir_err[1].cpu);
	free(r->redir_err[0].cpu);
	free(r->rx_cnt.cpu);
	free(r);
}

static double calc_period(struct record *r, struct record *p)
{
	double period_ = 0;
	__u64 period = 0;

	period = r->timestamp - p->timestamp;
	if (period > 0)
		period_ = ((double) period / NANOSEC_PER_SEC);

	return period_;
}

static __u64 calc_pps(struct datarec *r, struct datarec *p, double period_)
{
	__u64 packets = 0;
	__u64 pps = 0;

	if (period_ > 0) {
		packets = r->processed - p->processed;
		pps = packets / period_;
	}
	return pps;
}

static __u64 calc_drop_pps(struct datarec *r, struct datarec *p, double period_)
{
	__u64 packets = 0;
	__u64 pps = 0;

	if (period_ > 0) {
		packets = r->dropped - p->dropped;
		pps = packets / period_;
	}
	return pps;
}

static __u64 calc_errs_pps(struct datarec *r,
			    struct datarec *p, double period_)
{
	__u64 packets = 0;
	__u64 pps = 0;

	if (period_ > 0) {
		packets = r->issue - p->issue;
		pps = packets / period_;
	}
	return pps;
}

static __u64 calc_info_pps(struct datarec *r,
			   struct datarec *p, double period_)
{
	__u64 packets = 0;
	__u64 pps = 0;

	if (period_ > 0) {
		packets = r->info - p->info;
		pps = packets / period_;
	}
	return pps;
}

static void calc_xdp_pps(struct datarec *r, struct datarec *p,
			 double *xdp_pass, double *xdp_drop,
			 double *xdp_redirect, double period_)
{
	*xdp_pass = 0, *xdp_drop = 0, *xdp_redirect = 0;
	if (period_ > 0) {
		*xdp_redirect = (r->xdp_redirect - p->xdp_redirect) / period_;
		*xdp_pass = (r->xdp_pass - p->xdp_pass) / period_;
		*xdp_drop = (r->xdp_drop - p->xdp_drop) / period_;
	}
}

static void stats_print_rx_cnt(struct stats_record *stats_rec,
			       struct stats_record *stats_prev,
			       unsigned int nr_cpus)
{
	char *fmt_rx = "%-15s %-7d %'-14.0f %'-11.0f %'-10.0f %s\n";
	char *fm2_rx = "%-15s %-7s %'-14.0f %'-11.0f\n";
	struct record *rec, *prev;
	double t, pps, drop, err;
	char *errstr = "";
	int i;

	rec = &stats_rec->rx_cnt;
	prev = &stats_prev->rx_cnt;
	t = calc_period(rec, prev);
	for (i = 0; i < nr_cpus; i++) {
		struct datarec *r = &rec->cpu[i];
		struct datarec *p = &prev->cpu[i];

		pps = calc_pps(r, p, t);
		drop = calc_drop_pps(r, p, t);
		err = calc_errs_pps(r, p, t);
		if (err > 0)
			errstr = "cpu-dest/err";
		if (pps > 0)
			printf(fmt_rx, "XDP-RX", i, pps, drop, err, errstr);
	}
	pps = calc_pps(&rec->total, &prev->total, t);
	drop = calc_drop_pps(&rec->total, &prev->total, t);
	err = calc_errs_pps(&rec->total, &prev->total, t);
	printf(fm2_rx, "XDP-RX", "total", pps, drop);
}

static void stats_print_cpumap_enqueue(struct stats_record *stats_rec,
				       struct stats_record *stats_prev,
				       unsigned int nr_cpus)
{
	struct record *rec, *prev;
	double t, pps, drop, err;
	int i, to_cpu;

	/* cpumap enqueue stats */
	for (to_cpu = 0; to_cpu < n_cpus; to_cpu++) {
		char *fmt = "%-15s %3d:%-3d %'-14.0f %'-11.0f %'-10.2f %s\n";
		char *fm2 = "%-15s %3s:%-3d %'-14.0f %'-11.0f %'-10.2f %s\n";
		char *errstr = "";

		rec  =  &stats_rec->enq[to_cpu];
		prev = &stats_prev->enq[to_cpu];
		t = calc_period(rec, prev);
		for (i = 0; i < nr_cpus; i++) {
			struct datarec *r = &rec->cpu[i];
			struct datarec *p = &prev->cpu[i];

			pps  = calc_pps(r, p, t);
			drop = calc_drop_pps(r, p, t);
			err  = calc_errs_pps(r, p, t);
			if (err > 0) {
				errstr = "bulk-average";
				err = pps / err; /* calc average bulk size */
			}
			if (pps > 0)
				printf(fmt, "cpumap-enqueue",
				       i, to_cpu, pps, drop, err, errstr);
		}
		pps = calc_pps(&rec->total, &prev->total, t);
		if (pps > 0) {
			drop = calc_drop_pps(&rec->total, &prev->total, t);
			err  = calc_errs_pps(&rec->total, &prev->total, t);
			if (err > 0) {
				errstr = "bulk-average";
				err = pps / err; /* calc average bulk size */
			}
			printf(fm2, "cpumap-enqueue",
			       "sum", to_cpu, pps, drop, err, errstr);
		}
	}
}

static void stats_print_cpumap_kthread(struct stats_record *stats_rec,
				       struct stats_record *stats_prev,
				       unsigned int nr_cpus)
{
	char *fmt_k = "%-15s %-7d %'-14.0f %'-11.0f %'-10.0f %s\n";
	char *fm2_k = "%-15s %-7s %'-14.0f %'-11.0f %'-10.0f %s\n";
	struct record *rec, *prev;
	double t, pps, drop, err;
	char *e_str = "";
	int i;

	rec = &stats_rec->kthread;
	prev = &stats_prev->kthread;
	t = calc_period(rec, prev);
	for (i = 0; i < nr_cpus; i++) {
		struct datarec *r = &rec->cpu[i];
		struct datarec *p = &prev->cpu[i];

		pps = calc_pps(r, p, t);
		drop = calc_drop_pps(r, p, t);
		err = calc_errs_pps(r, p, t);
		if (err > 0)
			e_str = "sched";
		if (pps > 0)
			printf(fmt_k, "cpumap_kthread", i, pps, drop, err,
			       e_str);
	}
	pps = calc_pps(&rec->total, &prev->total, t);
	drop = calc_drop_pps(&rec->total, &prev->total, t);
	err = calc_errs_pps(&rec->total, &prev->total, t);
	if (err > 0)
		e_str = "sched-sum";
	printf(fm2_k, "cpumap_kthread", "total", pps, drop, err, e_str);
}

static void stats_print_redirect_cnt(struct stats_record *stats_rec,
				     struct stats_record *stats_prev,
				     unsigned int nr_cpus)
{
	char *fmt1 = "%-15s %-7d %'-14.0f %'-11.0f %s\n";
	char *fmt2 = "%-15s %-7s %'-14.0f %'-11.0f %s\n";
	struct record *rec, *prev;
	double t, pps;
	int i;

	rec = &stats_rec->redir_err[0];
	prev = &stats_prev->redir_err[0];
	t = calc_period(rec, prev);
	for (i = 0; i < nr_cpus; i++) {
		struct datarec *r = &rec->cpu[i];
		struct datarec *p = &prev->cpu[i];

		pps = calc_pps(r, p, t);
		if (pps > 0)
			printf(fmt1, "redirect", i, pps, 0.0, "Success");
	}
	pps = calc_pps(&rec->total, &prev->total, t);
	printf(fmt2, "redirect", "total", pps, 0.0, "Success");
}

static void stats_print_redirect_err_cnt(struct stats_record *stats_rec,
					 struct stats_record *stats_prev,
					 unsigned int nr_cpus)
{
	char *fmt1 = "%-15s %-7d %'-14.0f %'-11.0f %s\n";
	char *fmt2 = "%-15s %-7s %'-14.0f %'-11.0f %s\n";
	struct record *rec, *prev;
	double t, drop;
	int i;

	rec = &stats_rec->redir_err[1];
	prev = &stats_prev->redir_err[1];
	t = calc_period(rec, prev);
	for (i = 0; i < nr_cpus; i++) {
		struct datarec *r = &rec->cpu[i];
		struct datarec *p = &prev->cpu[i];

		drop = calc_drop_pps(r, p, t);
		if (drop > 0)
			printf(fmt1, "redirect", i, 0.0, drop, "Error");
	}
	drop = calc_drop_pps(&rec->total, &prev->total, t);
	printf(fmt2, "redirect", "total", 0.0, drop, "Error");
}

static void stats_print_exception_cnt(struct stats_record *stats_rec,
				      struct stats_record *stats_prev,
				      unsigned int nr_cpus)
{
	char *fmt1 = "%-15s %-7d %'-12.0f %'-12.0f %s\n";
	char *fmt2 = "%-15s %-7s %'-12.0f %'-12.0f %s\n";
	struct record *rec, *prev;
	double t, drop;
	int rec_i, i;

	for (rec_i = 0; rec_i < XDP_ACTION_MAX; rec_i++) {
		rec  = &stats_rec->exception[rec_i];
		prev = &stats_prev->exception[rec_i];
		t = calc_period(rec, prev);

		for (i = 0; i < nr_cpus; i++) {
			struct datarec *r = &rec->cpu[i];
			struct datarec *p = &prev->cpu[i];

			drop = calc_drop_pps(r, p, t);
			if (drop > 0)
				printf(fmt1, "xdp_exception", i,
				       0.0, drop, action2str(rec_i));
		}
		drop = calc_drop_pps(&rec->total, &prev->total, t);
		if (drop > 0)
			printf(fmt2, "xdp_exception", "total",
			       0.0, drop, action2str(rec_i));
	}
}

void sample_stats_print_cpumap_remote(struct stats_record *stats_rec,
				      struct stats_record *stats_prev,
				      unsigned int nr_cpus, char *mprog_name)
{
	char *fmt_k = "%-15s %-7d %'-14.0f %'-11.0f %'-10.0f\n";
	char *fm2_k = "%-15s %-7s %'-14.0f %'-11.0f %'-10.0f\n";
	double xdp_pass, xdp_drop, xdp_redirect;
	struct record *rec, *prev;
	double t;
	int i;

	printf("\n2nd remote XDP/eBPF prog_name: %s\n", mprog_name ?: "(none)");
	printf("%-15s %-7s %-14s %-11s %-9s\n", "XDP-cpumap", "CPU:to",
	       "xdp-pass", "xdp-drop", "xdp-redir");

	rec = &stats_rec->kthread;
	prev = &stats_prev->kthread;
	t = calc_period(rec, prev);
	for (i = 0; i < nr_cpus; i++) {
		struct datarec *r = &rec->cpu[i];
		struct datarec *p = &prev->cpu[i];

		calc_xdp_pps(r, p, &xdp_pass, &xdp_drop, &xdp_redirect, t);
		if (xdp_pass > 0 || xdp_drop > 0 || xdp_redirect > 0)
			printf(fmt_k, "xdp-in-kthread", i, xdp_pass, xdp_drop,
			       xdp_redirect);
	}
	calc_xdp_pps(&rec->total, &prev->total, &xdp_pass, &xdp_drop,
		     &xdp_redirect, t);
	printf(fm2_k, "xdp-in-kthread", "total", xdp_pass, xdp_drop,
	       xdp_redirect);
}

static void stats_print_devmap_xmit(struct stats_record *stats_rec,
				    struct stats_record *stats_prev,
				    unsigned int nr_cpus)
{
	char *fmt1 = "%-15s %-7d %'-14.0f %'-11.0f %'-10.0f %s %s\n";
	char *fmt2 = "%-15s %-7s %'-14.0f %'-11.0f %'-10.0f %s %s\n";
	double pps, drop, info, err;
	struct record *rec, *prev;
	char *err_str = "";
	char *i_str = "";
	double t;
	int i;

	rec = &stats_rec->devmap_xmit;
	prev = &stats_prev->devmap_xmit;
	t = calc_period(rec, prev);
	for (i = 0; i < nr_cpus; i++) {
		struct datarec *r = &rec->cpu[i];
		struct datarec *p = &prev->cpu[i];

		pps = calc_pps(r, p, t);
		drop = calc_drop_pps(r, p, t);
		info = calc_info_pps(r, p, t);
		err = calc_errs_pps(r, p, t);
		if (info > 0) {
			i_str = "bulk-average";
			info = (pps + drop) / info; /* calc avg bulk */
		}
		if (err > 0)
			err_str = "drv-err";
		if (pps > 0 || drop > 0)
			printf(fmt1, "devmap-xmit", i, pps, drop, info, i_str,
			       err_str);
	}
	pps = calc_pps(&rec->total, &prev->total, t);
	drop = calc_drop_pps(&rec->total, &prev->total, t);
	info = calc_info_pps(&rec->total, &prev->total, t);
	err = calc_errs_pps(&rec->total, &prev->total, t);
	if (info > 0) {
		i_str = "bulk-average";
		info = (pps + drop) / info; /* calc avg bulk */
	}
	if (err > 0)
		err_str = "drv-err";
	printf(fmt2, "devmap-xmit", "total", pps, drop, info, i_str, err_str);
}

static int init_tracepoints(struct bpf_object *obj)
{
	struct bpf_program *prog;

	bpf_object__for_each_program(prog, obj) {
		if (bpf_program__is_tracepoint(prog) != true)
			continue;

		tp_links[tp_cnt] = bpf_program__attach(prog);
		if (libbpf_get_error(tp_links[tp_cnt])) {
			tp_links[tp_cnt] = NULL;
			return -EINVAL;
		}
		tp_cnt++;
	}

	return 0;
}

static int init_map_fds(struct bpf_object *obj)
{
	enum map_type type;

	for (type = 0; type < NUM_MAP; type++) {
		map_fds[type] =
			bpf_object__find_map_fd_by_name(obj,
							map_type_strings[type]);

		if (map_fds[type] < 0)
			return -ENOENT;
	}

	return 0;
}

int sample_init(struct bpf_object *obj)
{
	n_cpus = get_nprocs_conf();
	return init_tracepoints(obj) ? : init_map_fds(obj);
}

void sample_exit(int status)
{
	while (tp_cnt)
		bpf_link__destroy(tp_links[--tp_cnt]);

	exit(status);
}

void sample_stats_collect(int mask, struct stats_record *rec)
{
	int i;

	if (mask & SAMPLE_RX_CNT)
		map_collect_percpu(map_fds[RX_CNT], 0, &rec->rx_cnt);

	/* Success case */
	if (mask & SAMPLE_REDIRECT_CNT)
		map_collect_percpu(map_fds[REDIRECT_ERR_CNT], 0, &rec->redir_err[0]);

	if (mask & SAMPLE_REDIRECT_ERR_CNT) {
		for (i = 1; i < XDP_REDIRECT_ERR_MAX; i++)
			map_collect_percpu(map_fds[REDIRECT_ERR_CNT], i, &rec->redir_err[i]);
	}

	if (mask & SAMPLE_CPUMAP_ENQUEUE_CNT)
		for (i = 0; i < n_cpus; i++)
			map_collect_percpu(map_fds[CPUMAP_ENQUEUE_CNT], i, &rec->enq[i]);

	if (mask & SAMPLE_CPUMAP_KTHREAD_CNT)
		map_collect_percpu(map_fds[CPUMAP_KTHREAD_CNT], 0, &rec->kthread);

	if (mask & SAMPLE_EXCEPTION_CNT)
		for (i = 0; i < XDP_ACTION_MAX; i++)
			map_collect_percpu(map_fds[EXCEPTION_CNT], i, &rec->exception[i]);

	if (mask & SAMPLE_DEVMAP_XMIT_CNT)
		map_collect_percpu(map_fds[DEVMAP_XMIT_CNT], 0, &rec->devmap_xmit);
}

void sample_stats_print(int mask, struct stats_record *cur,
			struct stats_record *prev, char *prog_name)
{
	int nr_cpus = bpf_num_possible_cpus();

	printf("Running XDP/eBPF prog_name:%s\n", prog_name ?: "(none)");
	printf("%-15s %-7s %-14s %-11s %-9s\n",
	       "XDP-event", "CPU:to", "pps", "drop-pps", "extra-info");

	if (mask & SAMPLE_RX_CNT)
		stats_print_rx_cnt(cur, prev, nr_cpus);

	if (mask & SAMPLE_REDIRECT_CNT)
		stats_print_redirect_cnt(cur, prev, nr_cpus);

	if (mask & SAMPLE_REDIRECT_ERR_CNT)
		stats_print_redirect_err_cnt(cur, prev, nr_cpus);

	if (mask & SAMPLE_CPUMAP_ENQUEUE_CNT)
		stats_print_cpumap_enqueue(cur, prev, nr_cpus);

	if (mask & SAMPLE_CPUMAP_KTHREAD_CNT)
		stats_print_cpumap_kthread(cur, prev, nr_cpus);

	if (mask & SAMPLE_EXCEPTION_CNT)
		stats_print_exception_cnt(cur, prev, nr_cpus);

	if (mask & SAMPLE_DEVMAP_XMIT_CNT)
		stats_print_devmap_xmit(cur, prev, nr_cpus);
}

void sample_stats_poll(int interval, int mask, char *prog_name, int use_separators)
{
	struct stats_record *record, *prev;

	record = alloc_stats_record();
	prev   = alloc_stats_record();
	sample_stats_collect(mask, record);

	/* Trick to pretty printf with thousands separators use %' */
	if (use_separators)
		setlocale(LC_NUMERIC, "en_US");

	for (;;) {
		swap(&prev, &record);
		sample_stats_collect(mask, record);
		sample_stats_print(mask, record, prev, NULL);
		printf("\n");
		fflush(stdout);
		sleep(interval);
	}

	free_stats_record(record);
	free_stats_record(prev);
}

const char *get_driver_name(int ifindex)
{
	struct ethtool_drvinfo drv = {};
	char ifname[IF_NAMESIZE];
	static char drvname[32];
	struct ifreq ifr = {};
	int fd, r;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return NULL;

	if (!if_indextoname(ifindex, ifname))
		goto end;

	drv.cmd = ETHTOOL_GDRVINFO;
	strncpy(ifr.ifr_name, ifname, IF_NAMESIZE);
	ifr.ifr_data = (void *)&drv;

	r = ioctl(fd, SIOCETHTOOL, &ifr);
	if (r)
		goto end;

	strncpy(drvname, drv.driver, sizeof(drvname));

	close(fd);
	return drvname;

end:
	close(fd);
	return NULL;
}

int get_mac_addr(int ifindex, void *mac_addr)
{
	char ifname[IF_NAMESIZE];
	struct ifreq ifr = {};
	int fd, r;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -errno;

	if (!if_indextoname(ifindex, ifname)) {
		r = -errno;
		goto end;
	}

	strncpy(ifr.ifr_name, ifname, IF_NAMESIZE);

	r = ioctl(fd, SIOCGIFHWADDR, &ifr);
	if (r) {
		r = -errno;
		goto end;
	}

	memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6 * sizeof(char));

end:
	close(fd);
	return r;
}
