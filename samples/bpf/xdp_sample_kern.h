// SPDX-License-Identifier: GPL-2.0
/*  GPLv2, Copyright(c) 2017 Jesper Dangaard Brouer, Red Hat, Inc. */
#pragma once

#include <uapi/linux/bpf.h>
#include <net/xdp.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

#ifndef NR_CPUS
#define NR_CPUS 64
#endif

#define MAX_CPUS NR_CPUS

#define EINVAL 22
#define ENETDOWN 100
#define EMSGSIZE 90
#define EOPNOTSUPP 95

/* Common stats data record to keep userspace more simple */
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

/* Count RX packets, as XDP bpf_prog doesn't get direct TX-success
 * feedback.  Redirect TX errors can be caught via a tracepoint.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct datarec);
	__uint(max_entries, 1);
} rx_cnt SEC(".maps");

/* Used by trace point */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct datarec);
	__uint(max_entries, 2
			    + 1 /* EINVAL */
			    + 1 /* ENETDOWN */
			    + 1 /* EMSGSIZE */
			    + 1 /* EOPNOTSUPP */);
} redirect_err_cnt SEC(".maps");

/* Used by trace point */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct datarec);
	__uint(max_entries, MAX_CPUS);
} cpumap_enqueue_cnt SEC(".maps");

/* Used by trace point */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct datarec);
	__uint(max_entries, 1);
} cpumap_kthread_cnt SEC(".maps");

#define XDP_UNKNOWN (XDP_REDIRECT + 1)
/* Used by trace point */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct datarec);
	__uint(max_entries, XDP_UNKNOWN + 1);
} exception_cnt SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct datarec);
	__uint(max_entries, 1);
} devmap_xmit_cnt SEC(".maps");

/*** Trace point code ***/

enum {
	XDP_REDIRECT_SUCCESS = 0,
	XDP_REDIRECT_ERROR = 1
};

static __always_inline
__u32 xdp_get_err_key(int err)
{
	switch (err) {
	case 0:
		return 0;
	case -EINVAL:
		return 2;
	case -ENETDOWN:
		return 3;
	case -EMSGSIZE:
		return 4;
	case -EOPNOTSUPP:
		return 5;
	default:
		return 1;
	}
}

static __always_inline
int xdp_redirect_collect_stat(struct bpf_raw_tracepoint_args *ctx)
{
	u32 key = XDP_REDIRECT_ERROR;
	int err = ctx->args[3];
	struct datarec *rec;

	key = xdp_get_err_key(err);

	rec = bpf_map_lookup_elem(&redirect_err_cnt, &key);
	if (!rec)
		return 0;
	if (key)
		rec->dropped++;
	else
		rec->processed++;

	return 0; /* Indicate event was filtered (no further processing)*/
	/*
	 * Returning 1 here would allow e.g. a perf-record tracepoint
	 * to see and record these events, but it doesn't work well
	 * in-practice as stopping perf-record also unload this
	 * bpf_prog.  Plus, there is additional overhead of doing so.
	 */
}

SEC("raw_tracepoint/xdp_redirect_err")
int trace_xdp_redirect_err(struct bpf_raw_tracepoint_args *ctx)
{
	return xdp_redirect_collect_stat(ctx);
}

SEC("raw_tracepoint/xdp_redirect_map_err")
int trace_xdp_redirect_map_err(struct bpf_raw_tracepoint_args *ctx)
{
	return xdp_redirect_collect_stat(ctx);
}

SEC("raw_tracepoint/xdp_redirect")
int trace_xdp_redirect(struct bpf_raw_tracepoint_args *ctx)
{
	return xdp_redirect_collect_stat(ctx);
}

SEC("raw_tracepoint/xdp_redirect_map")
int trace_xdp_redirect_map(struct bpf_raw_tracepoint_args *ctx)
{
	return xdp_redirect_collect_stat(ctx);
}

SEC("raw_tracepoint/xdp_exception")
int trace_xdp_exception(struct bpf_raw_tracepoint_args *ctx)
{
	u32 key = ctx->args[2];
	struct datarec *rec;

	if (key > XDP_REDIRECT)
		key = XDP_UNKNOWN;

	rec = bpf_map_lookup_elem(&exception_cnt, &key);
	if (!rec)
		return 1;
	rec->dropped += 1;

	return 0;
}

SEC("raw_tracepoint/xdp_cpumap_enqueue")
int trace_xdp_cpumap_enqueue(struct bpf_raw_tracepoint_args *ctx)
{
	u32 to_cpu = ctx->args[3];
	struct datarec *rec;

	if (to_cpu >= MAX_CPUS)
		return 1;

	rec = bpf_map_lookup_elem(&cpumap_enqueue_cnt, &to_cpu);
	if (!rec)
		return 0;
	rec->processed += ctx->args[1];
	rec->dropped   += ctx->args[2];

	/* Record bulk events, then userspace can calc average bulk size */
	if (ctx->args[1] > 0)
		rec->issue += 1;

	/* Inception: It's possible to detect overload situations, via
	 * this tracepoint.  This can be used for creating a feedback
	 * loop to XDP, which can take appropriate actions to mitigate
	 * this overload situation.
	 */
	return 0;
}

SEC("raw_tracepoint/xdp_cpumap_kthread")
int trace_xdp_cpumap_kthread(struct bpf_raw_tracepoint_args *ctx)
{
	struct xdp_cpumap_stats *stats;
	struct datarec *rec;
	u32 key = 0;

	stats = (struct xdp_cpumap_stats *) ctx->args[4];
	if (!stats)
		return 0;

	rec = bpf_map_lookup_elem(&cpumap_kthread_cnt, &key);
	if (!rec)
		return 0;
	rec->processed += ctx->args[1];
	rec->dropped   += ctx->args[2];

	rec->xdp_pass  += BPF_CORE_READ(stats, pass);
	rec->xdp_drop  += BPF_CORE_READ(stats, drop);
	rec->xdp_redirect  += BPF_CORE_READ(stats, redirect);

	/* Count times kthread yielded CPU via schedule call */
	if (ctx->args[3])
		rec->issue++;

	return 0;
}

SEC("raw_tracepoint/xdp_devmap_xmit")
int trace_xdp_devmap_xmit(struct bpf_raw_tracepoint_args *ctx)
{
	struct datarec *rec;
	u32 key = 0;
	int drops;

	rec = bpf_map_lookup_elem(&devmap_xmit_cnt, &key);
	if (!rec)
		return 0;
	rec->processed += ctx->args[2];
	rec->dropped   += ctx->args[3];

	/* Record bulk events, then userspace can calc average bulk size */
	rec->info += 1;

	/* Record error cases, where no frame were sent */
	if (ctx->args[4])
		rec->issue++;

	drops = ctx->args[3];
	/* Catch API error of drv ndo_xdp_xmit sent more than count */
	if (drops < 0)
		rec->issue++;

	return 1;
}
