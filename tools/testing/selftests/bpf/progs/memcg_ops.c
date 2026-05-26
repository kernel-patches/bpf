// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define ONE_SECOND_NS	1000000000

struct local_config {
	u64 threshold;
	u64 high_cgroup_id;
	bool use_below_low;
	bool use_below_min;
	unsigned int over_high_ms;
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

SEC("tp/memcg/count_memcg_events")
int
handle_count_memcg_events(struct trace_event_raw_memcg_rstat_events *ctx)
{
	u32 key = 0;
	struct AggregationData *data;
	u64 current_ts;

	if (ctx->id != local_config.high_cgroup_id ||
	    (ctx->item != PGFAULT))
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
	if (!local_config.use_below_low)
		return false;

	return need_threshold();
}

SEC("struct_ops/below_min")
bool below_min_impl(struct mem_cgroup *memcg, unsigned long emin,
		    unsigned long usage)
{
	if (!local_config.use_below_min)
		return false;

	return need_threshold();
}

SEC("struct_ops/memcg_charged")
unsigned int memcg_charged_impl(struct mem_cgroup *memcg, unsigned int nr_pages)
{
	if (local_config.over_high_ms && need_threshold())
		return local_config.over_high_ms;

	return 0;
}

SEC(".struct_ops.link")
struct memcg_bpf_ops high_mcg_ops = {
	.below_low = (void *)below_low_impl,
	.below_min = (void *)below_min_impl,
};

SEC(".struct_ops.link")
struct memcg_bpf_ops low_mcg_ops = {
	.memcg_charged = (void *)memcg_charged_impl,
};

char LICENSE[] SEC("license") = "GPL";
