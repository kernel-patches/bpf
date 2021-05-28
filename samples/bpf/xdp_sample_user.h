// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <bpf/libbpf.h>

enum map_type {
	RX_CNT,
	REDIRECT_ERR_CNT,
	CPUMAP_ENQUEUE_CNT,
	CPUMAP_KTHREAD_CNT,
	EXCEPTION_CNT,
	DEVMAP_XMIT_CNT,
	NUM_MAP,
};

enum tp_type {
	TP_REDIRECT_CNT,
	TP_REDIRECT_MAP_CNT,
	TP_REDIRECT_ERR_CNT,
	TP_REDIRECT_MAP_ERR_CNT,
	TP_CPUMAP_ENQUEUE_CNT,
	TP_CPUMAP_KTHREAD_CNT,
	TP_EXCEPTION_CNT,
	TP_DEVMAP_XMIT_CNT,
	NUM_TP,
};

enum stats_mask {
	_SAMPLE_REDIRECT_MAP        = 1U << 0,
	SAMPLE_RX_CNT               = 1U << 1,
	SAMPLE_REDIRECT_ERR_CNT     = 1U << 2,
	SAMPLE_CPUMAP_ENQUEUE_CNT   = 1U << 3,
	SAMPLE_CPUMAP_KTHREAD_CNT   = 1U << 4,
	SAMPLE_EXCEPTION_CNT        = 1U << 5,
	SAMPLE_DEVMAP_XMIT_CNT      = 1U << 6,
	SAMPLE_REDIRECT_CNT         = 1U << 7,
	SAMPLE_REDIRECT_MAP_CNT     = SAMPLE_REDIRECT_CNT | _SAMPLE_REDIRECT_MAP,
	SAMPLE_REDIRECT_ERR_MAP_CNT = SAMPLE_REDIRECT_ERR_CNT | _SAMPLE_REDIRECT_MAP,
};

static const char *const map_type_strings[] = {
	[RX_CNT] = "rx_cnt",
	[REDIRECT_ERR_CNT] = "redirect_err_cnt",
	[CPUMAP_ENQUEUE_CNT] = "cpumap_enqueue_cnt",
	[CPUMAP_KTHREAD_CNT] = "cpumap_kthread_cnt",
	[EXCEPTION_CNT] = "exception_cnt",
	[DEVMAP_XMIT_CNT] = "devmap_xmit_cnt",
};

enum log_level {
	LL_DEFAULT = 1U << 0,
	LL_SIMPLE  = 1U << 1,
	LL_DEBUG   = 1U << 2,
};

extern struct bpf_link *tp_links[NUM_TP];
extern int map_fds[NUM_MAP];
extern int n_cpus;
extern int tp_cnt;
extern enum log_level sample_log_level;

/* Exit return codes */
#define EXIT_OK			0
#define EXIT_FAIL		1
#define EXIT_FAIL_OPTION	2
#define EXIT_FAIL_XDP		3
#define EXIT_FAIL_BPF		4
#define EXIT_FAIL_MEM		5

#define XDP_REDIRECT_ERR_MAX 6

__attribute__((unused)) static const char *xdp_redirect_err_names[XDP_REDIRECT_ERR_MAX] = {
	/* Key=1 keeps unknown errors */
	"Success", "Unknown", "EINVAL", "ENETDOWN", "EMSGSIZE",
	"EOPNOTSUPP",
};

/* enum xdp_action */
#define XDP_UNKNOWN (XDP_REDIRECT + 1)
#define XDP_ACTION_MAX (XDP_UNKNOWN + 1)

static const char *xdp_action_names[XDP_ACTION_MAX] = {
	[XDP_ABORTED]	= "XDP_ABORTED",
	[XDP_DROP]	= "XDP_DROP",
	[XDP_PASS]	= "XDP_PASS",
	[XDP_TX]	= "XDP_TX",
	[XDP_REDIRECT]	= "XDP_REDIRECT",
	[XDP_UNKNOWN]	= "XDP_UNKNOWN",
};

__attribute__((unused)) static inline const char *action2str(int action)
{
	if (action < XDP_ACTION_MAX)
		return xdp_action_names[action];
	return NULL;
}

/* Common stats data record shared with _kern.c */
struct datarec {
	__u64 processed;
	__u64 dropped;
	__u64 issue;
	union {
		__u64 xdp_pass;
		__u64 info;
	};
	__u64 xdp_drop;
	__u64 xdp_redirect;
};

struct record {
	__u64 timestamp;
	struct datarec total;
	struct datarec *cpu;
};

struct stats_record {
	struct record rx_cnt;
	struct record redir_err[XDP_REDIRECT_ERR_MAX];
	struct record kthread;
	struct record exception[XDP_ACTION_MAX];
	struct record devmap_xmit;
	struct record enq[];
};

struct sample_output {
	struct {
		__u64 rx;
		__u64 redir;
		__u64 drop;
		__u64 err;
		__u64 xmit;
	} totals;
	struct {
		__u64 pps;
		__u64 drop;
		__u64 err;
	} rx_cnt;
	struct {
		__u64 suc;
		__u64 err;
	} redir_cnt;
	struct {
		__u64 hits;
	} except_cnt;
	struct {
		__u64 pps;
		__u64 drop;
		__u64 err;
		double bavg;
	} xmit_cnt;
};

int sample_init(struct bpf_object *obj);
void sample_exit(int status);
struct stats_record *alloc_stats_record(void);
void free_stats_record(struct stats_record *rec);
void sample_stats_print(int mask, struct stats_record *cur,
			struct stats_record *prev, char *prog_name,
			int interval);
void sample_stats_collect(int mask, struct stats_record *rec);
void sample_summary_update(struct sample_output *out, int interval);
void sample_summary_print(void);
void sample_calc_timediff(struct timespec *cur, const struct timespec *prev,
			  int interval);
void sample_stats_poll(int interval, int mask, char *prog_name,
		       int use_separators);
void sample_stats_print_cpumap_remote(struct stats_record *stats_rec,
				      struct stats_record *stats_prev,
				      unsigned int nr_cpus, char *mprog_name);
void sample_reset_mode(void);

const char *get_driver_name(int ifindex);
int get_mac_addr(int ifindex, void *mac_addr);

/* Pointer swap trick */
static inline void swap(struct stats_record **a, struct stats_record **b)
{
	struct stats_record *tmp;

	tmp = *a;
	*a = *b;
	*b = tmp;
}
