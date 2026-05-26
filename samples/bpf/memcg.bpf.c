// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define ONE_SECOND_NS		1000000000
#define ONE_MB_PAGE_COUNT 256

/* GFP flags needed by bpf_try_to_free_mem_cgroup_pages() */
#define BIT(nr)			(1UL << (nr))
#define ___GFP_IO		BIT(___GFP_IO_BIT)
#define ___GFP_FS		BIT(___GFP_FS_BIT)
#define ___GFP_DIRECT_RECLAIM	BIT(___GFP_DIRECT_RECLAIM_BIT)
#define ___GFP_KSWAPD_RECLAIM	BIT(___GFP_KSWAPD_RECLAIM_BIT)
#define __GFP_IO		((gfp_t)___GFP_IO)
#define __GFP_FS		((gfp_t)___GFP_FS)
#define __GFP_DIRECT_RECLAIM	((gfp_t)___GFP_DIRECT_RECLAIM)
#define __GFP_KSWAPD_RECLAIM	((gfp_t)___GFP_KSWAPD_RECLAIM)
#define __GFP_RECLAIM ((gfp_t)(___GFP_DIRECT_RECLAIM|___GFP_KSWAPD_RECLAIM))
#define GFP_KERNEL		(__GFP_RECLAIM | __GFP_IO | __GFP_FS)

#define MEMCG_RECLAIM_MAY_SWAP (1 << 1)
#define MEMCG_RECLAIM_PROACTIVE (1 << 2)

#define ASYNC_FREE_BATCH	32
#define ASYNC_FREE_LOOP_MAX	16

#define READ_ONCE(x) (*(volatile typeof(x) *)&(x))
#define WRITE_ONCE(x, val) ((*(volatile typeof(x) *)&(x)) = (val))

struct local_config {
	u64		threshold;
	u64		high_cgroup_id;
	u64		low_cgroup_id;
	bool		use_below_low;
	bool		use_below_min;
	unsigned int	over_high_ms;
	u64		async_trigger_bytes;
} local_config;

struct AggregationData {
	u64 sum;
	u64 window_start_ts;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct AggregationData);
} aggregation_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} trigger_ts_map SEC(".maps");

struct wq_elem {
	struct bpf_wq work;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct wq_elem);
} wq_map SEC(".maps");

static s64 allocated;
static s64 old_allocated;
/*
 * async_free_run: 0 = idle, 1 = workqueue item is queued/running.
 * Acts as a one-shot guard: only one reclaim task is in-flight at
 * a time.  Cleared by async_free() once reclaim is complete and
 * re-armed by __memcg_charged_impl() on the next trigger.
 */
static u64 async_free_run;

/*
 * wq_initialized: flipped from 0 -> 1 by prog_init() to make init
 * idempotent if prog_init() is called more than once.
 */
static u64 wq_initialized;

struct cgroup_memcg {
	struct cgroup	 *cgrp;
	struct mem_cgroup *memcg;
};

static int get_cgroup_memcg_from_id(u64 cgroup_id, struct cgroup_memcg *cm)
{
	cm->cgrp = bpf_cgroup_from_id(cgroup_id);
	if (!cm->cgrp)
		return -1;

	cm->memcg = bpf_get_mem_cgroup(&cm->cgrp->self);
	if (!cm->memcg) {
		bpf_cgroup_release(cm->cgrp);
		return -1;
	}
	return 0;
}

static void put_cgroup_memcg(struct cgroup_memcg *cm)
{
	bpf_put_mem_cgroup(cm->memcg);
	bpf_cgroup_release(cm->cgrp);
}

static int async_free(void *map, int *key, void *value)
{
	struct cgroup_memcg cm;
	bool started_wq = false;
	int i;

	if (get_cgroup_memcg_from_id(local_config.low_cgroup_id, &cm) != 0)
		return 0;

	for (i = 0; i < ASYNC_FREE_LOOP_MAX; i++) {
		if (bpf_try_to_free_mem_cgroup_pages(cm.memcg, ASYNC_FREE_BATCH,
						     GFP_KERNEL,
						     MEMCG_RECLAIM_MAY_SWAP,
						     -1) <= 0)
			break;

		if (bpf_mem_cgroup_usage(cm.memcg) <
		    local_config.async_trigger_bytes)
			break;
	}

	if (i == ASYNC_FREE_LOOP_MAX) {
		__u32 k = 0;
		struct wq_elem *elem = bpf_map_lookup_elem(&wq_map, &k);

		if (elem) {
			bpf_wq_start(&elem->work, 0);
			started_wq = true;
		}
	}

	put_cgroup_memcg(&cm);

	if (!started_wq)
		__atomic_exchange_n(&async_free_run, 0, __ATOMIC_RELEASE);
	return 0;
}

SEC("syscall")
int prog_init(struct local_config *ctx)
{
	struct wq_elem *elem;
	__u32 key = 0;
	u64 expected = 0;
	int ret = -1;

	/* Guard against double-initialisation */
	if (!__atomic_compare_exchange_n(&wq_initialized, &expected, 1,
					 false,
					 __ATOMIC_ACQ_REL,
					 __ATOMIC_RELAXED))
		goto out;

	elem = bpf_map_lookup_elem(&wq_map, &key);
	if (!elem)
		goto out;
	ret = bpf_wq_init(&elem->work, &wq_map, 0);
	if (ret)
		goto out;
	ret = bpf_wq_set_callback(&elem->work, async_free, 0);
	if (ret)
		goto out;

	allocated = 0;
	async_free_run = 0;
	__builtin_memcpy(&local_config, ctx, sizeof(local_config));

out:
	return ret;
}

SEC("tp/memcg/count_memcg_events")
int handle_count_memcg_events(
		struct trace_event_raw_memcg_rstat_events *ctx)
{
	u32 key = 0;
	struct AggregationData *data;
	u64 current_ts;

	if (ctx->id != local_config.high_cgroup_id ||
	    ctx->item != PGFAULT)
		goto out;

	data = bpf_map_lookup_elem(&aggregation_map, &key);
	if (!data)
		goto out;

	current_ts = bpf_ktime_get_ns();

	if (current_ts - data->window_start_ts < ONE_SECOND_NS) {
		data->sum += ctx->val;
	} else {
		data->window_start_ts = current_ts;
		data->sum = ctx->val;
	}

	if (data->sum > local_config.threshold) {
		bpf_map_update_elem(&trigger_ts_map, &key, &current_ts,
				    BPF_ANY);
		data->sum = 0;
		data->window_start_ts = current_ts;
	}

out:
	return 0;
}

static bool need_threshold(void)
{
	u32 key = 0;
	u64 *trigger_ts;
	bool ret = false;
	u64 current_ts;

	trigger_ts = bpf_map_lookup_elem(&trigger_ts_map, &key);
	if (!trigger_ts || *trigger_ts == 0)
		goto out;

	current_ts = bpf_ktime_get_ns();
	if (current_ts - *trigger_ts < ONE_SECOND_NS)
		ret = true;

out:
	return ret;
}

SEC("struct_ops/below_low")
bool below_low_impl(struct mem_cgroup *memcg, unsigned long elow,
		    unsigned long usage)
{
	return need_threshold();
}

SEC("struct_ops/below_min")
bool below_min_impl(struct mem_cgroup *memcg, unsigned long elow,
		    unsigned long usage)
{
	return need_threshold();
}

static u64 get_usage(void)
{
	u64 ret = 0;
	struct cgroup_memcg cm;

	if (get_cgroup_memcg_from_id(local_config.low_cgroup_id, &cm) != 0)
		return 0;

	ret = bpf_mem_cgroup_usage(cm.memcg);

	put_cgroup_memcg(&cm);

	return ret;
}

static __always_inline s64 abs_diff(s64 a, s64 b)
{
	return a > b ? a - b : b - a;
}

static __always_inline unsigned int
__memcg_charged_impl(struct mem_cgroup *memcg, unsigned int nr_pages)
{
	struct wq_elem *elem;
	__u32 key = 0;
	u64 expected = 0;
	s64 cur_allocated;
	s64 cur_old_allocated;

	__atomic_add_fetch(&allocated, nr_pages, __ATOMIC_RELAXED);
	cur_allocated = READ_ONCE(allocated);
	cur_old_allocated = READ_ONCE(old_allocated);
	if (abs_diff(cur_allocated, cur_old_allocated) < ONE_MB_PAGE_COUNT)
		goto out;
	WRITE_ONCE(old_allocated, cur_allocated);

	if (get_usage() < local_config.async_trigger_bytes)
		goto out;

	if (__atomic_compare_exchange_n(&async_free_run,
					&expected, 1,
					false,
					__ATOMIC_ACQ_REL,
					__ATOMIC_RELAXED)) {
		elem = bpf_map_lookup_elem(&wq_map, &key);
		if (!elem)
			return 0;

		bpf_wq_start(&elem->work, 0);
	}

out:
	return 0;
}

SEC("struct_ops/memcg_charged")
unsigned int BPF_PROG(memcg_charged_impl, struct mem_cgroup *memcg,
		      unsigned int nr_pages)
{
	return __memcg_charged_impl(memcg, nr_pages);
}

SEC("struct_ops/memcg_uncharged")
void BPF_PROG(memcg_uncharged_impl, struct mem_cgroup *memcg,
	      unsigned int nr_pages)
{
	__atomic_sub_fetch(&allocated, nr_pages, __ATOMIC_RELAXED);
}

unsigned int
__get_high_delay_ms_impl(struct mem_cgroup *memcg, unsigned int nr_pages)
{
	if (need_threshold())
		return local_config.over_high_ms;

	return 0;
}

SEC("struct_ops/memcg_charged")
unsigned int BPF_PROG(get_high_delay_ms_impl, struct mem_cgroup *memcg,
		      unsigned int nr_pages)
{
	return __get_high_delay_ms_impl(memcg, nr_pages);
}

SEC("struct_ops/memcg_charged")
unsigned int BPF_PROG(low_mcg_impl, struct mem_cgroup *memcg,
		      unsigned int nr_pages)
{
	__memcg_charged_impl(memcg, nr_pages);

	return __get_high_delay_ms_impl(memcg, nr_pages);
}

SEC(".struct_ops.link")
struct memcg_bpf_ops high_mcg_ops = {
	.below_low = (void *)below_low_impl,
	.below_min = (void *)below_min_impl,
};

SEC(".struct_ops.link")
struct memcg_bpf_ops high_mcg_ops_below_low = {
	.below_low = (void *)below_low_impl,
};

SEC(".struct_ops.link")
struct memcg_bpf_ops high_mcg_ops_below_min = {
	.below_min = (void *)below_min_impl,
};

SEC(".struct_ops.link")
struct memcg_bpf_ops low_mcg_ops = {
	.memcg_charged = (void *)low_mcg_impl,
	.memcg_uncharged = (void *)memcg_uncharged_impl,
};

SEC(".struct_ops.link")
struct memcg_bpf_ops low_mcg_ops_high_delay = {
	.memcg_charged = (void *)get_high_delay_ms_impl,
};

SEC(".struct_ops.link")
struct memcg_bpf_ops low_mcg_ops_async = {
	.memcg_charged = (void *)memcg_charged_impl,
	.memcg_uncharged = (void *)memcg_uncharged_impl,
};

char LICENSE[] SEC("license") = "GPL";
