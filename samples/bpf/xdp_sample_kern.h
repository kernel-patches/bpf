// SPDX-License-Identifier: GPL-2.0
/*  GPLv2, Copyright(c) 2017 Jesper Dangaard Brouer, Red Hat, Inc. */
#pragma once

#include <uapi/linux/bpf.h>
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

/* Tracepoint format: /sys/kernel/debug/tracing/events/xdp/xdp_redirect/format
 * Code in:                kernel/include/trace/events/xdp.h
 */
struct xdp_redirect_ctx {
	u64 __pad;	// First 8 bytes are not accessible by bpf code
	int prog_id;	//	offset:8;  size:4; signed:1;
	u32 act;	//	offset:12  size:4; signed:0;
	int ifindex;	//	offset:16  size:4; signed:1;
	int err;	//	offset:20  size:4; signed:1;
	int to_ifindex;	//	offset:24  size:4; signed:1;
	u32 map_id;	//	offset:28  size:4; signed:0;
	int map_index;	//	offset:32  size:4; signed:1;
};			//	offset:36

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
int xdp_redirect_collect_stat(struct xdp_redirect_ctx *ctx)
{
	u32 key = XDP_REDIRECT_ERROR;
	struct datarec *rec;
	int err = ctx->err;

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

SEC("tracepoint/xdp/xdp_redirect_err")
int trace_xdp_redirect_err(struct xdp_redirect_ctx *ctx)
{
	return xdp_redirect_collect_stat(ctx);
}

SEC("tracepoint/xdp/xdp_redirect_map_err")
int trace_xdp_redirect_map_err(struct xdp_redirect_ctx *ctx)
{
	return xdp_redirect_collect_stat(ctx);
}

/* Likely unloaded when prog starts */
SEC("tracepoint/xdp/xdp_redirect")
int trace_xdp_redirect(struct xdp_redirect_ctx *ctx)
{
	return xdp_redirect_collect_stat(ctx);
}

/* Likely unloaded when prog starts */
SEC("tracepoint/xdp/xdp_redirect_map")
int trace_xdp_redirect_map(struct xdp_redirect_ctx *ctx)
{
	return xdp_redirect_collect_stat(ctx);
}

/* Tracepoint format: /sys/kernel/debug/tracing/events/xdp/xdp_exception/format
 * Code in:                kernel/include/trace/events/xdp.h
 */
struct xdp_exception_ctx {
	u64 __pad;	// First 8 bytes are not accessible by bpf code
	int prog_id;	//	offset:8;  size:4; signed:1;
	u32 act;	//	offset:12; size:4; signed:0;
	int ifindex;	//	offset:16; size:4; signed:1;
};

SEC("tracepoint/xdp/xdp_exception")
int trace_xdp_exception(struct xdp_exception_ctx *ctx)
{
	struct datarec *rec;
	u32 key = ctx->act;

	if (key > XDP_REDIRECT)
		key = XDP_UNKNOWN;

	rec = bpf_map_lookup_elem(&exception_cnt, &key);
	if (!rec)
		return 1;
	rec->dropped += 1;

	return 0;
}

/* Tracepoint: /sys/kernel/debug/tracing/events/xdp/xdp_cpumap_enqueue/format
 * Code in:         kernel/include/trace/events/xdp.h
 */
struct cpumap_enqueue_ctx {
	u64 __pad;		// First 8 bytes are not accessible by bpf code
	int map_id;		//	offset:8;  size:4; signed:1;
	u32 act;		//	offset:12; size:4; signed:0;
	int cpu;		//	offset:16; size:4; signed:1;
	unsigned int drops;	//	offset:20; size:4; signed:0;
	unsigned int processed;	//	offset:24; size:4; signed:0;
	int to_cpu;		//	offset:28; size:4; signed:1;
};

SEC("tracepoint/xdp/xdp_cpumap_enqueue")
int trace_xdp_cpumap_enqueue(struct cpumap_enqueue_ctx *ctx)
{
	u32 to_cpu = ctx->to_cpu;
	struct datarec *rec;

	if (to_cpu >= MAX_CPUS)
		return 1;

	rec = bpf_map_lookup_elem(&cpumap_enqueue_cnt, &to_cpu);
	if (!rec)
		return 0;
	rec->processed += ctx->processed;
	rec->dropped   += ctx->drops;

	/* Record bulk events, then userspace can calc average bulk size */
	if (ctx->processed > 0)
		rec->issue += 1;

	/* Inception: It's possible to detect overload situations, via
	 * this tracepoint.  This can be used for creating a feedback
	 * loop to XDP, which can take appropriate actions to mitigate
	 * this overload situation.
	 */
	return 0;
}

/* Tracepoint: /sys/kernel/debug/tracing/events/xdp/xdp_cpumap_kthread/format
 * Code in:         kernel/include/trace/events/xdp.h
 */
struct cpumap_kthread_ctx {
	u64 __pad;			// First 8 bytes are not accessible
	int map_id;			//	offset:8;  size:4; signed:1;
	u32 act;			//	offset:12; size:4; signed:0;
	int cpu;			//	offset:16; size:4; signed:1;
	unsigned int drops;		//	offset:20; size:4; signed:0;
	unsigned int processed;		//	offset:24; size:4; signed:0;
	int sched;			//	offset:28; size:4; signed:1;
	unsigned int xdp_pass;		//	offset:32; size:4; signed:0;
	unsigned int xdp_drop;		//	offset:36; size:4; signed:0;
	unsigned int xdp_redirect;	//	offset:40; size:4; signed:0;
};

SEC("tracepoint/xdp/xdp_cpumap_kthread")
int trace_xdp_cpumap_kthread(struct cpumap_kthread_ctx *ctx)
{
	struct datarec *rec;
	u32 key = 0;

	rec = bpf_map_lookup_elem(&cpumap_kthread_cnt, &key);
	if (!rec)
		return 0;
	rec->processed += ctx->processed;
	rec->dropped   += ctx->drops;
	rec->xdp_pass  += ctx->xdp_pass;
	rec->xdp_drop  += ctx->xdp_drop;
	rec->xdp_redirect  += ctx->xdp_redirect;

	/* Count times kthread yielded CPU via schedule call */
	if (ctx->sched)
		rec->issue++;

	return 0;
}

/* Tracepoint: /sys/kernel/debug/tracing/events/xdp/xdp_devmap_xmit/format
 * Code in:         kernel/include/trace/events/xdp.h
 */
struct devmap_xmit_ctx {
	u64 __pad;		// First 8 bytes are not accessible by bpf code
	int from_ifindex;	//	offset:8;  size:4; signed:1;
	u32 act;		//	offset:12; size:4; signed:0;
	int to_ifindex;		//	offset:16; size:4; signed:1;
	int drops;		//	offset:20; size:4; signed:1;
	int sent;		//	offset:24; size:4; signed:1;
	int err;		//	offset:28; size:4; signed:1;
};

SEC("tracepoint/xdp/xdp_devmap_xmit")
int trace_xdp_devmap_xmit(struct devmap_xmit_ctx *ctx)
{
	struct datarec *rec;
	u32 key = 0;

	rec = bpf_map_lookup_elem(&devmap_xmit_cnt, &key);
	if (!rec)
		return 0;
	rec->processed += ctx->sent;
	rec->dropped   += ctx->drops;

	/* Record bulk events, then userspace can calc average bulk size */
	rec->info += 1;

	/* Record error cases, where no frame were sent */
	if (ctx->err)
		rec->issue++;

	/* Catch API error of drv ndo_xdp_xmit sent more than count */
	if (ctx->drops < 0)
		rec->issue++;

	return 1;
}
