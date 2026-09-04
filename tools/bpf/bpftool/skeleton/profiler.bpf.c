// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Copyright (c) 2020 Facebook
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct bpf_perf_event_value___local {
	__u64 counter;
	__u64 enabled;
	__u64 running;
} __attribute__((preserve_access_index));

struct profile_reading {
	struct bpf_perf_event_value___local value;
	bool armed;
};

/* map of perf event fds, num_cpu * num_metric entries */
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(int));
} events SEC(".maps");

/* readings at fentry */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct profile_reading));
} fentry_readings SEC(".maps");

/* accumulated readings */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct bpf_perf_event_value___local));
} accum_readings SEC(".maps");

/* sample counts, one per cpu */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
} counts SEC(".maps");

const volatile __u32 num_cpu = 1;
const volatile __u32 num_metric = 1;
#define MAX_NUM_METRICS 4
#define min(a, b) ({ typeof(a) _a = (a); typeof(b) _b = (b); _a < _b ? _a : _b; })

SEC("fentry/XXX")
int BPF_PROG(fentry_XXX)
{
	struct bpf_perf_event_value___local readings[MAX_NUM_METRICS];
	struct profile_reading *ptrs[MAX_NUM_METRICS];
	u32 key = bpf_get_smp_processor_id();
	u32 nr_metrics = min(num_metric, MAX_NUM_METRICS);
	u32 i;

	/* look up before reading, to reduce error */
	for (i = 0; i < nr_metrics; i++) {
		u32 flag = i;

		ptrs[i] = bpf_map_lookup_elem(&fentry_readings, &flag);
		if (!ptrs[i])
			return 0;
		ptrs[i]->armed = false;
	}

	for (i = 0; i < nr_metrics; i++) {
		int err;

		err = bpf_perf_event_read_value(&events, key, (void *)&readings[i],
						sizeof(readings[i]));
		if (err)
			return 0;
		key += num_cpu;
	}

	for (i = 0; i < nr_metrics; i++) {
		ptrs[i]->value = readings[i];
		ptrs[i]->armed = true;
	}

	return 0;
}

static inline void
fexit_update_maps(u32 id, struct bpf_perf_event_value___local *after)
{
	struct profile_reading *before;
	struct bpf_perf_event_value___local diff;
	struct bpf_perf_event_value___local *accum;

	before = bpf_map_lookup_elem(&fentry_readings, &id);
	if (!before || !before->armed)
		return;
	before->armed = false;

	diff.counter = after->counter - before->value.counter;
	diff.enabled = after->enabled - before->value.enabled;
	diff.running = after->running - before->value.running;

	accum = bpf_map_lookup_elem(&accum_readings, &id);
	if (!accum)
		return;

	accum->counter += diff.counter;
	accum->enabled += diff.enabled;
	accum->running += diff.running;
}

SEC("fexit/XXX")
int BPF_PROG(fexit_XXX)
{
	struct bpf_perf_event_value___local readings[MAX_NUM_METRICS];
	u32 cpu = bpf_get_smp_processor_id();
	u32 nr_metrics = min(num_metric, MAX_NUM_METRICS);
	u32 i, zero = 0;
	int err;
	u64 *count;

	/* read all events before updating the maps, to reduce error */
	for (i = 0; i < nr_metrics; i++) {
		err = bpf_perf_event_read_value(&events, cpu + i * num_cpu,
						(void *)(readings + i),
						sizeof(*readings));
		if (err)
			return 0;
	}
	count = bpf_map_lookup_elem(&counts, &zero);
	if (!count)
		return 0;

	*count += 1;
	for (i = 0; i < nr_metrics; i++)
		fexit_update_maps(i, &readings[i]);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
