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
#include <math.h>
#include <locale.h>
#include <sys/signalfd.h>
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

#include <fcntl.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <sys/utsname.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "bpf_util.h"
#include "xdp_sample_user.h"

struct bpf_link *tp_links[NUM_TP] = {};
int map_fds[NUM_MAP], tp_cnt, n_cpus;
static int sample_sig_fd;
enum log_level sample_log_level = LL_SIMPLE;
static struct sample_output sum_out;
static bool err_exp;

#define __sample_print(fmt, cond, printer, ...)                                \
	({                                                                     \
		if (cond)                                                      \
			printer(fmt, ##__VA_ARGS__);                           \
	})

#define print_always(fmt, ...) __sample_print(fmt, 1, printf, ##__VA_ARGS__)
#define print_default(fmt, ...)                                                \
	__sample_print(fmt, sample_log_level & LL_DEFAULT, printf, ##__VA_ARGS__)
#define __print_err(err, fmt, printer, ...)                                    \
	({                                                                     \
		__sample_print(fmt, err > 0 || sample_log_level & LL_DEFAULT,  \
			       printer, ##__VA_ARGS__);                        \
		err_exp = err_exp ? true : err > 0;                            \
	})
#define print_err(err, fmt, ...) __print_err(err, fmt, printf, ##__VA_ARGS__)

#define print_link_err(err, str, width, type)                                  \
	__print_err(err, str, print_link, width, type)

#define __COLUMN(x) "%'10" x " %-13s"
#define FMT_COLUMNf __COLUMN(".0f")
#define FMT_COLUMNd __COLUMN("d")
#define FMT_COLUMNl __COLUMN("llu")
#define RX(rx) rx, "rx/s"
#define PPS(pps) pps, "pkt/s"
#define DROP(drop) drop, "drop/s"
#define ERR(err) err, "error/s"
#define HITS(hits) hits, "hit/s"
#define XMIT(xmit) xmit, "xmit/s"
#define PASS(pass) pass, "pass/s"
#define REDIR(redir) redir, "redir/s"

void sample_print_help(int mask)
{
	printf("Output format description\n\n"
	       "By default, redirect success statistics are disabled, use -s to enable.\n"
	       "The terse output mode is default, verbose mode can be activated using -v\n"
	       "Use SIGQUIT (Ctrl + \\) to switch the mode dynamically at runtime\n\n"
	       "Terse mode displays at most the following fields:\n"
	       "  rx/s     Number of packets received per second\n"
	       "  redir/s  Number of packets successfully redirected per second\n"
	       "  error/s  Aggregated count of errors per second (including dropped packets)\n"
	       "  xmit/s   Number of packets transmitted on the output device per second\n\n"
	       "Output description for verbose mode:\n"
	       "  FIELD         DESCRIPTION\n");
	if (mask & SAMPLE_RX_CNT) {
		printf("  receive\tDisplays the number of packets received & errors encountered\n"
		       " \t\tWhenever an error or packet drop occurs, details of per CPU error\n"
		       " \t\tand drop statistics will be expanded inline in terse mode.\n"
		       " \t\t\tpkt/s     - Packets received per second\n"
		       " \t\t\tdrop/s    - Packets dropped per second\n"
		       " \t\t\terror/s   - Errors encountered per second\n\n");
	}
	if (mask & (SAMPLE_REDIRECT_CNT|SAMPLE_REDIRECT_ERR_CNT)) {
		printf("  redirect\tDisplays the number of packets successfully redirected\n"
		       "  \t\tErrors encountered are expanded under redirect_err field\n"
		       "  \t\tNote that passing -s to enable it has a per packet overhead\n"
		       "  \t\t\tredir/s   - Packets redirected successfully per second\n\n"
		       "  redirect_err\tDisplays the number of packets that failed redirection\n"
		       "  \t\tThe errno is expanded under this field with per CPU count\n"
		       "  \t\tThe recognized errors are EOPNOTSUPP, EINVAL, ENETDOWN and EMSGSIZE\n"
		       "  \t\t\terror/s   - Packets that failed redirection per second\n\n");
	}

	if (mask & SAMPLE_EXCEPTION_CNT) {
		printf("  xdp_exception\tDisplays xdp_exception tracepoint events\n"
		       "  \t\tThis can occur due to internal driver errors, unrecognized\n"
		       "  \t\tXDP actions and due to explicit user trigger by use of XDP_ABORTED\n"
		       "  \t\tEach action is expanded below this field with its count\n"
		       "  \t\t\thit/s     - Number of times the tracepoint was hit per second\n\n");
	}

	if (mask & SAMPLE_DEVMAP_XMIT_CNT) {
		printf("  devmap_xmit\tDisplays devmap_xmit tracepoint events\n"
		       "  \t\tThis tracepoint is invoked for successful transmissions on output\n"
		       "  \t\tdevice but these statistics are not available for generic XDP mode,\n"
		       "  \t\thence they will be omitted from the output when using SKB mode\n"
		       "  \t\t\txmit/s    - Number of packets that were transmitted per second\n"
		       "  \t\t\tdrop/s    - Number of packets that failed transmissions per second\n"
		       "  \t\t\tdrv_err/s - Number of internal driver errors per second\n"
		       "  \t\t\tbulk_avg  - Average number of packets processed for each event\n\n");
	}
}

static const char *elixir_search[NUM_TP] = {
	[TP_REDIRECT_CNT] = "_trace_xdp_redirect",
	[TP_REDIRECT_MAP_CNT] = "_trace_xdp_redirect_map",
	[TP_REDIRECT_ERR_CNT] = "_trace_xdp_redirect_err",
	[TP_REDIRECT_MAP_ERR_CNT] = "_trace_xdp_redirect_map_err",
	[TP_CPUMAP_ENQUEUE_CNT] = "trace_xdp_cpumap_enqueue",
	[TP_CPUMAP_KTHREAD_CNT] = "trace_xdp_cpumap_kthread",
	[TP_EXCEPTION_CNT] = "trace_xdp_exception",
	[TP_DEVMAP_XMIT_CNT] = "trace_xdp_devmap_xmit",
};

static const char *make_url(enum tp_type i)
{
	const char *key = elixir_search[i];
	static struct utsname uts = {};
	static char url[128];
	static bool uts_init;
	int maj, min;
	char c[2];

	if (!uts_init) {
		if (uname(&uts) < 0)
			return NULL;
		uts_init = true;
	}

	if (!key || sscanf(uts.release, "%d.%d%1s", &maj, &min, c) != 3)
		return NULL;

	snprintf(url, sizeof(url), "https://elixir.bootlin.com/linux/v%d.%d/C/ident/%s",
		 maj, min, key);

	return url;
}

static void print_link(const char *str, int width, enum tp_type i)
{
	static int t = -1;
	const char *s;
	int fd, l;

	if (t < 0) {
		fd = open("/proc/self/fd/1", O_RDONLY);
		if (fd < 0)
			return;
		t = isatty(fd);
		close(fd);
	}

	s = make_url(i);
	if (!s || !t) {
		printf("  %-*s", width, str);
		return;
	}

	l = strlen(str);
	width = width - l > 0 ? width - l : 0;
	printf("  \x1B]8;;%s\a%s\x1B]8;;\a%*c", s, str, width, ' ');
}

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
	for (i = 0; i < XDP_REDIRECT_ERR_MAX; i++)
		rec->redir_err[i].cpu = alloc_record_per_cpu();
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
	for (i = 0; i < XDP_REDIRECT_ERR_MAX; i++)
		free(r->redir_err[i].cpu);
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

static double sample_round(double val)
{
	if (val - floor(val) < 0.5)
		return floor(val);
	return ceil(val);
}

static __u64 calc_pps(struct datarec *r, struct datarec *p, double period_)
{
	__u64 packets = 0;
	__u64 pps = 0;

	if (period_ > 0) {
		packets = r->processed - p->processed;
		pps = sample_round(packets / period_);
	}
	return pps;
}

static __u64 calc_drop_pps(struct datarec *r, struct datarec *p, double period_)
{
	__u64 packets = 0;
	__u64 pps = 0;

	if (period_ > 0) {
		packets = r->dropped - p->dropped;
		pps = sample_round(packets / period_);
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
		pps = sample_round(packets / period_);
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
		pps = sample_round(packets / period_);
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

static void stats_get_rx_cnt(struct stats_record *stats_rec,
			     struct stats_record *stats_prev,
			     unsigned int nr_cpus, struct sample_output *out)
{
	struct record *rec, *prev;
	double t, pps, drop, err;
	int i;

	rec = &stats_rec->rx_cnt;
	prev = &stats_prev->rx_cnt;
	t = calc_period(rec, prev);

	for (i = 0; i < nr_cpus; i++) {
		struct datarec *r = &rec->cpu[i];
		struct datarec *p = &prev->cpu[i];
		char str[256];

		pps = calc_pps(r, p, t);
		if (!pps)
			continue;

		snprintf(str, sizeof(str), "cpu:%d", i);

		drop = calc_drop_pps(r, p, t);
		err = calc_errs_pps(r, p, t);
		print_default("          %-12s " FMT_COLUMNf FMT_COLUMNf FMT_COLUMNf "\n",
			      str, PPS(pps), DROP(drop), ERR(err));
	}

	if (out) {
		pps = calc_pps(&rec->total, &prev->total, t);
		drop = calc_drop_pps(&rec->total, &prev->total, t);
		err = calc_errs_pps(&rec->total, &prev->total, t);

		out->rx_cnt.pps = pps;
		out->rx_cnt.drop = drop;
		out->rx_cnt.err = err;
		out->totals.rx += pps;
		out->totals.drop += drop;
		out->totals.err += err;
	}
}

static void stats_get_cpumap_enqueue(struct stats_record *stats_rec,
				     struct stats_record *stats_prev,
				     unsigned int nr_cpus)
{
	struct record *rec, *prev;
	double t, pps, drop, err;
	int i, to_cpu;

	/* cpumap enqueue stats */
	for (to_cpu = 0; to_cpu < n_cpus; to_cpu++) {
		rec  =  &stats_rec->enq[to_cpu];
		prev = &stats_prev->enq[to_cpu];
		t = calc_period(rec, prev);

		pps = calc_pps(&rec->total, &prev->total, t);
		drop = calc_drop_pps(&rec->total, &prev->total, t);
		err = calc_errs_pps(&rec->total, &prev->total, t);

		if (pps > 0) {
			char str[256];

			snprintf(str, sizeof(str), "enqueue to cpu %d", to_cpu);

			if (err > 0)
				err = pps / err; /* calc average bulk size */

			print_link_err(drop, str, 20, TP_CPUMAP_ENQUEUE_CNT);
			print_err(drop,
				  " " FMT_COLUMNf FMT_COLUMNf __COLUMN(".2f") "\n",
				  PPS(pps), DROP(drop), err, "bulk_avg");
		}

		for (i = 0; i < nr_cpus; i++) {
			struct datarec *r = &rec->cpu[i];
			struct datarec *p = &prev->cpu[i];
			char str[256];

			pps  = calc_pps(r, p, t);
			if (!pps)
				continue;

			snprintf(str, sizeof(str), "cpu:%d->%d", i, to_cpu);

			drop = calc_drop_pps(r, p, t);
			err  = calc_errs_pps(r, p, t);
			if (err > 0)
				err = pps / err; /* calc average bulk size */
			print_default("          %-12s " FMT_COLUMNf FMT_COLUMNf
				      __COLUMN(".2f") "\n", str, PPS(pps), DROP(drop),
				      err, "bulk_avg");
		}
	}
}

static void stats_get_cpumap_kthread(struct stats_record *stats_rec,
				     struct stats_record *stats_prev,
				     unsigned int nr_cpus)
{
	struct record *rec, *prev;
	double t, pps, drop, err;
	int i;

	rec = &stats_rec->kthread;
	prev = &stats_prev->kthread;
	t = calc_period(rec, prev);

	pps = calc_pps(&rec->total, &prev->total, t);
	drop = calc_drop_pps(&rec->total, &prev->total, t);
	err = calc_errs_pps(&rec->total, &prev->total, t);

	print_link_err(drop, pps ? "kthread total" : "kthread", 20, TP_CPUMAP_KTHREAD_CNT);
	print_err(drop, " " FMT_COLUMNf FMT_COLUMNf FMT_COLUMNf "\n",
			  PPS(pps), DROP(drop), err, "sched");

	for (i = 0; i < nr_cpus; i++) {
		struct datarec *r = &rec->cpu[i];
		struct datarec *p = &prev->cpu[i];
		char str[256];

		pps = calc_pps(r, p, t);
		if (!pps)
			continue;

		snprintf(str, sizeof(str), "cpu:%d", i);

		drop = calc_drop_pps(r, p, t);
		err = calc_errs_pps(r, p, t);
		print_default("          %-12s " FMT_COLUMNf FMT_COLUMNf FMT_COLUMNf "\n",
			      str, PPS(pps), DROP(drop), err, "sched");
	}
}

static void stats_get_redirect_cnt(struct stats_record *stats_rec,
				   struct stats_record *stats_prev,
				   unsigned int nr_cpus, struct sample_output *out)
{
	struct record *rec, *prev;
	double t, pps;
	int i;

	rec = &stats_rec->redir_err[0];
	prev = &stats_prev->redir_err[0];
	t = calc_period(rec, prev);
	for (i = 0; i < nr_cpus; i++) {
		struct datarec *r = &rec->cpu[i];
		struct datarec *p = &prev->cpu[i];
		char str[256];

		pps = calc_pps(r, p, t);
		if (!pps)
			continue;

		snprintf(str, sizeof(str), "cpu:%d", i);

		print_default("           %-11s " FMT_COLUMNf "\n", str, REDIR(pps));
	}

	if (out) {
		pps = calc_pps(&rec->total, &prev->total, t);
		out->redir_cnt.suc = pps;
		out->totals.redir += pps;
	}

}

static void stats_get_redirect_err_cnt(struct stats_record *stats_rec,
				       struct stats_record *stats_prev,
				       unsigned int nr_cpus, struct sample_output *out)
{
	struct record *rec, *prev;
	double t, drop, sum = 0;
	int rec_i, i;

	for (rec_i = 1; rec_i < XDP_REDIRECT_ERR_MAX; rec_i++) {
		char str[256];
		int l = 0;

		rec = &stats_rec->redir_err[rec_i];
		prev = &stats_prev->redir_err[rec_i];
		t = calc_period(rec, prev);

		drop = calc_drop_pps(&rec->total, &prev->total, t);
		if (drop > 0 && !out) {
			l = snprintf(str, sizeof(str),
				     sample_log_level & LL_DEFAULT ?
						   "%s total" :
						   "%s",
				     xdp_redirect_err_names[rec_i]);
			l = l >= sizeof(str) ? sizeof(str) - 1 : l;
			print_err(drop, "    %-18s " FMT_COLUMNf "\n", str,
				      ERR(drop));
		}

		for (i = 0; i < nr_cpus; i++) {
			struct datarec *r = &rec->cpu[i];
			struct datarec *p = &prev->cpu[i];
			double drop;
			int sp, ll;

			drop = calc_drop_pps(r, p, t);
			if (!drop)
				continue;

			ll = snprintf(str, sizeof(str), "cpu:%d", i);
			ll = ll >= sizeof(str) ? sizeof(str) - 1 : ll;

			sp = l - ll > 0 ? l - ll : 0;
			ll = 19 - sp > 0 ? 19 - sp : 0;

			/* Align dynamically under error string */
			print_default("    %*c%-*s" FMT_COLUMNf "\n", sp, ' ', ll, str, ERR(drop));
		}

		sum += drop;
	}

	if (out) {
		out->redir_cnt.err = sum;
		out->totals.err += sum;
	}
}

static void stats_get_exception_cnt(struct stats_record *stats_rec,
				    struct stats_record *stats_prev,
				    unsigned int nr_cpus, struct sample_output *out)
{
	double t, drop, sum = 0;
	struct record *rec, *prev;
	int rec_i;


	for (rec_i = 0; rec_i < XDP_ACTION_MAX; rec_i++) {
		rec  = &stats_rec->exception[rec_i];
		prev = &stats_prev->exception[rec_i];
		t = calc_period(rec, prev);

		drop = calc_drop_pps(&rec->total, &prev->total, t);
		/* Fold out errors after heading */
		if (drop > 0 && !out)
			print_always("    %-18s " FMT_COLUMNf "\n", action2str(rec_i), ERR(drop));
		sum += drop;
	}

	if (out) {
		out->except_cnt.hits = sum;
		out->totals.err += sum;
	}
}

void sample_stats_print_cpumap_remote(struct stats_record *stats_rec,
				      struct stats_record *stats_prev,
				      unsigned int nr_cpus, char *mprog_name)
{
	double xdp_pass, xdp_drop, xdp_redirect;
	struct record *rec, *prev;
	double t;
	int i;

	print_default("\n2nd remote XDP/eBPF prog_name: %s\n", mprog_name ?: "(none)");

	rec = &stats_rec->kthread;
	prev = &stats_prev->kthread;
	t = calc_period(rec, prev);
	for (i = 0; i < nr_cpus; i++) {
		struct datarec *r = &rec->cpu[i];
		struct datarec *p = &prev->cpu[i];
		char str[256];

		calc_xdp_pps(r, p, &xdp_pass, &xdp_drop, &xdp_redirect, t);
		if (!xdp_pass || !xdp_drop || !xdp_redirect)
			continue;

		snprintf(str, sizeof(str), "cpu:%d", i);
		print_default("                 %-5s " FMT_COLUMNf FMT_COLUMNf FMT_COLUMNf "\n",
			      str, PASS(xdp_pass), DROP(xdp_drop), REDIR(xdp_redirect));
	}
	calc_xdp_pps(&rec->total, &prev->total, &xdp_pass, &xdp_drop,
		     &xdp_redirect, t);
	print_default("  %-20s " FMT_COLUMNf FMT_COLUMNf FMT_COLUMNf "\n",
		      "xdp_in_kthread total", PASS(xdp_pass), DROP(xdp_drop), REDIR(xdp_redirect));
}

static void stats_get_devmap_xmit(struct stats_record *stats_rec,
				  struct stats_record *stats_prev,
				  unsigned int nr_cpus, struct sample_output *out)
{
	double pps, drop, info, err;
	struct record *rec, *prev;
	double t;
	int i;

	rec = &stats_rec->devmap_xmit;
	prev = &stats_prev->devmap_xmit;
	t = calc_period(rec, prev);
	for (i = 0; i < nr_cpus; i++) {
		struct datarec *r = &rec->cpu[i];
		struct datarec *p = &prev->cpu[i];
		char str[256];

		pps = calc_pps(r, p, t);
		drop = calc_drop_pps(r, p, t);

		if (!pps)
			continue;

		snprintf(str, sizeof(str), "cpu:%d", i);

		info = calc_info_pps(r, p, t);
		err = calc_errs_pps(r, p, t);
		if (info > 0)
			info = (pps + drop) / info; /* calc avg bulk */
		print_default("              %-9s" FMT_COLUMNf FMT_COLUMNf
			      FMT_COLUMNf __COLUMN(".2f") "\n",
			      str, XMIT(pps), DROP(drop), err, "drv_err/s",
			      info, "bulk_avg");
	}
	if (out) {
		pps = calc_pps(&rec->total, &prev->total, t);
		drop = calc_drop_pps(&rec->total, &prev->total, t);
		info = calc_info_pps(&rec->total, &prev->total, t);
		if (info > 0)
			info = (pps + drop) / info; /* calc avg bulk */
		err = calc_errs_pps(&rec->total, &prev->total, t);

		out->xmit_cnt.pps = pps;
		out->xmit_cnt.drop = drop;
		out->xmit_cnt.bavg = info;
		out->xmit_cnt.err = err;
		out->totals.xmit += pps;
		out->totals.err += err;
	}
}

static void stats_print(const char *prefix, int mask, struct stats_record *r,
			struct stats_record *p, struct sample_output *out)
{
	int nr_cpus = bpf_num_possible_cpus();
	const char *str;

	print_always("%-23s", prefix ?: "Summary");
	if (mask & SAMPLE_RX_CNT)
		print_always(FMT_COLUMNl, RX(out->totals.rx));
	if (mask & SAMPLE_REDIRECT_CNT)
		print_always(FMT_COLUMNl, REDIR(out->totals.redir));
	printf(FMT_COLUMNl, ERR(out->totals.err + out->totals.drop));
	if (mask & SAMPLE_DEVMAP_XMIT_CNT)
		printf(FMT_COLUMNl, XMIT(out->totals.xmit));
	printf("\n");

	if (mask & SAMPLE_RX_CNT) {
		str = (sample_log_level & LL_DEFAULT) && out->rx_cnt.pps ?
			"receive total" : "receive";
		print_err(
			(out->rx_cnt.err || out->rx_cnt.drop),
			"  %-20s " FMT_COLUMNl FMT_COLUMNl FMT_COLUMNl "\n",
			str, PPS(out->rx_cnt.pps), DROP(out->rx_cnt.drop),
			ERR(out->rx_cnt.err));

		stats_get_rx_cnt(r, p, nr_cpus, NULL);
	}

	if (mask & SAMPLE_CPUMAP_ENQUEUE_CNT)
		stats_get_cpumap_enqueue(r, p, nr_cpus);
	if (mask & SAMPLE_CPUMAP_KTHREAD_CNT)
		stats_get_cpumap_kthread(r, p, nr_cpus);

	if (mask & SAMPLE_REDIRECT_CNT) {
		str = out->redir_cnt.suc ? "redirect total" : "redirect";
		print_link_err(0, str, 20, mask & _SAMPLE_REDIRECT_MAP ?
				TP_REDIRECT_MAP_CNT : TP_REDIRECT_CNT);
		print_default(" " FMT_COLUMNl "\n", REDIR(out->redir_cnt.suc));

		stats_get_redirect_cnt(r, p, nr_cpus, NULL);
	}

	if (mask & SAMPLE_REDIRECT_ERR_CNT) {
		str = (sample_log_level & LL_DEFAULT) && out->redir_cnt.err ?
			"redirect_err total" : "redirect_err";
		print_link_err(out->redir_cnt.err, str, 20, mask & _SAMPLE_REDIRECT_MAP ?
			       TP_REDIRECT_MAP_ERR_CNT : TP_REDIRECT_ERR_CNT);
		print_err(out->redir_cnt.err, "  %-20s " FMT_COLUMNl "\n", str,
			  ERR(out->redir_cnt.err));

		stats_get_redirect_err_cnt(r, p, nr_cpus, NULL);
	}

	if (mask & SAMPLE_EXCEPTION_CNT) {
		str = out->except_cnt.hits ? "xdp_exception total" : "xdp_exception";

		print_link_err(out->except_cnt.hits, str, 20, TP_EXCEPTION_CNT);
		print_err(out->except_cnt.hits, " " FMT_COLUMNl "\n", HITS(out->except_cnt.hits));

		stats_get_exception_cnt(r, p, nr_cpus, NULL);
	}

	if (mask & SAMPLE_DEVMAP_XMIT_CNT) {
		str = (sample_log_level & LL_DEFAULT) && out->xmit_cnt.pps ?
			"devmap_xmit total" : "devmap_xmit";

		print_link_err(out->xmit_cnt.err, str, 20, TP_DEVMAP_XMIT_CNT);
		print_err(out->xmit_cnt.err,
			  " " FMT_COLUMNl FMT_COLUMNl FMT_COLUMNl __COLUMN(".2f") "\n",
			  XMIT(out->xmit_cnt.pps), DROP(out->xmit_cnt.drop),
			  out->xmit_cnt.err, "drv_err/s", out->xmit_cnt.bavg, "bulk_avg");

		stats_get_devmap_xmit(r, p, nr_cpus, NULL);
	}

	if (sample_log_level & LL_DEFAULT || ((sample_log_level & LL_SIMPLE) && err_exp)) {
		err_exp = false;
		printf("\n");
	}
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
	sigset_t st;

	n_cpus = get_nprocs_conf();

	sigemptyset(&st);
	sigaddset(&st, SIGQUIT);

	if (sigprocmask(SIG_BLOCK, &st, NULL) < 0)
		return -errno;

	sample_sig_fd = signalfd(-1, &st, SFD_CLOEXEC|SFD_NONBLOCK);
	if (sample_sig_fd < 0)
		return -errno;

	return init_tracepoints(obj) ? : init_map_fds(obj);
}

void sample_reset_mode(void)
{
	struct signalfd_siginfo si;
	int r;

	r = read(sample_sig_fd, &si, sizeof(si));
	if (r < 0) {
		if (errno == EAGAIN)
			return;
		return;
	}

	if (si.ssi_signo == SIGQUIT) {
		sample_log_level ^= LL_DEBUG - 1;
		printf("\n");
	}
}

void sample_exit(int status)
{
	while (tp_cnt)
		bpf_link__destroy(tp_links[--tp_cnt]);
	sample_summary_print();
	close(sample_sig_fd);
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

void sample_summary_update(struct sample_output *out, int interval)
{
	sum_out.totals.rx += out->totals.rx;
	sum_out.totals.redir += out->totals.redir;
	sum_out.totals.drop += out->totals.drop;
	sum_out.totals.err += out->totals.err;
	sum_out.totals.xmit += out->totals.xmit;
	sum_out.rx_cnt.pps += interval;
}

void sample_summary_print(void)
{
	double period = sum_out.rx_cnt.pps;

	print_always("\nTotals\n");
	if (sum_out.totals.rx) {
		double pkts = sum_out.totals.rx;

		print_always("  Packets received    : %'-10llu\n", sum_out.totals.rx);
		print_always("  Average packets/s   : %'-10.0f\n", sample_round(pkts/period));
	}
	if (sum_out.totals.redir) {
		double pkts = sum_out.totals.redir;

		print_always("  Packets redirected  : %'-10llu\n", sum_out.totals.redir);
		print_always("  Average redir/s     : %'-10.0f\n", sample_round(pkts/period));
	}
	print_always("  Packets dropped     : %'-10llu\n", sum_out.totals.drop);
	print_always("  Errors recorded     : %'-10llu\n", sum_out.totals.err);
	if (sum_out.totals.xmit) {
		double pkts = sum_out.totals.xmit;

		print_always("  Packets transmitted : %'-10llu\n", sum_out.totals.xmit);
		print_always("  Average transmit/s  : %'-10.0f\n", sample_round(pkts/period));
	}
}

void sample_stats_print(int mask, struct stats_record *cur,
			struct stats_record *prev, char *prog_name,
			int interval)
{
	struct sample_output out = {};

	if (mask & SAMPLE_RX_CNT)
		stats_get_rx_cnt(cur, prev, 0, &out);

	if (mask & SAMPLE_REDIRECT_CNT)
		stats_get_redirect_cnt(cur, prev, 0, &out);

	if (mask & SAMPLE_REDIRECT_ERR_CNT)
		stats_get_redirect_err_cnt(cur, prev, 0, &out);

	if (mask & SAMPLE_EXCEPTION_CNT)
		stats_get_exception_cnt(cur, prev, 0, &out);

	if (mask & SAMPLE_DEVMAP_XMIT_CNT)
		stats_get_devmap_xmit(cur, prev, 0, &out);

	sample_summary_update(&out, interval);

	stats_print(prog_name, mask, cur, prev, &out);
}

static void calc_timediff(struct timespec *cur, const struct timespec *prev)
{
	if (cur->tv_nsec - prev->tv_nsec < 0) {
		cur->tv_sec = cur->tv_sec - prev->tv_sec - 1;
		cur->tv_nsec = cur->tv_nsec - prev->tv_nsec + NANOSEC_PER_SEC;
	} else {
		cur->tv_sec -= prev->tv_sec;
		cur->tv_nsec -= prev->tv_nsec;
	}
}

void sample_calc_timediff(struct timespec *cur, const struct timespec *prev, int interval)
{
	struct timespec ts = { .tv_sec = interval };

	calc_timediff(cur, prev);
	calc_timediff(&ts, cur);
	*cur = ts;
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
		struct timespec ots, nts;

		clock_gettime(CLOCK_MONOTONIC, &ots);
		swap(&prev, &record);
		sample_stats_collect(mask, record);
		sample_stats_print(mask, record, prev, prog_name, interval);
		fflush(stdout);
		clock_gettime(CLOCK_MONOTONIC, &nts);
		sample_calc_timediff(&nts, &ots, interval);
		nanosleep(&nts, NULL);
		sample_reset_mode();
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
