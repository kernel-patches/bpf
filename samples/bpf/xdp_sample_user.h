// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <bpf/libbpf.h>

enum map_type {
	RX_CNT,
	REDIRECT_ERR_CNT,
	CPUMAP_ENQUEUE_CNT,
	CPUMAP_KTHREAD_CNT,
	EXCEPTION_CNT,
	NUM_MAP,
};

enum tp_type {
	TP_REDIRECT_ERR_CNT,
	TP_REDIRECT_MAP_ERR_CNT,
	TP_CPUMAP_ENQUEUE_CNT,
	TP_CPUMAP_KTHREAD_CNT,
	TP_EXCEPTION_CNT,
	NUM_TP,
};

enum stats_mask {
	SAMPLE_RX_CNT	        = 1U << 1,
	SAMPLE_REDIRECT_ERR_CNT	= 1U << 2,
	SAMPLE_CPUMAP_ENQUEUE_CNT  = 1U << 3,
	SAMPLE_CPUMAP_KTHREAD_CNT  = 1U << 4,
	SAMPLE_EXCEPTION_CNT	= 1U << 5,
};

static const char *const map_type_strings[] = {
	[RX_CNT] = "rx_cnt",
	[REDIRECT_ERR_CNT] = "redirect_err_cnt",
	[CPUMAP_ENQUEUE_CNT] = "cpumap_enqueue_cnt",
	[CPUMAP_KTHREAD_CNT] = "cpumap_kthread_cnt",
	[EXCEPTION_CNT] = "exception_cnt",
};

extern struct bpf_link *tp_links[NUM_TP];
extern int map_fds[NUM_MAP];
extern int n_cpus;
extern int tp_cnt;

/* Exit return codes */
#define EXIT_OK			0
#define EXIT_FAIL		1
#define EXIT_FAIL_OPTION	2
#define EXIT_FAIL_XDP		3
#define EXIT_FAIL_BPF		4
#define EXIT_FAIL_MEM		5

/* Common stats data record shared with _kern.c */
struct datarec {
	__u64 processed;
	__u64 dropped;
	__u64 issue;
	__u64 xdp_pass;
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
	struct record redir_err;
	struct record kthread;
	struct record exception;
	struct record enq[];
};

int sample_init(struct bpf_object *obj);
void sample_exit(int status);
struct stats_record *alloc_stats_record(void);
void free_stats_record(struct stats_record *rec);
void sample_stats_print(int mask, struct stats_record *cur,
			struct stats_record *prev, char *prog_name);
void sample_stats_collect(int mask, struct stats_record *rec);
void sample_stats_poll(int interval, int mask, char *prog_name,
		       int use_separators);
void sample_stats_print_cpumap_remote(struct stats_record *stats_rec,
				      struct stats_record *stats_prev,
				      unsigned int nr_cpus, char *mprog_name);

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
