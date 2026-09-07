// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Copyright (c) 2020 Facebook
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct profile_reading {
	struct bpf_perf_event_value value;
	bool armed;
};

/* map of perf event fds, num_cpu * num_metric entries */
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(int));
} events SEC(".maps");

/* readings at fentry */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct profile_reading));
	__uint(max_entries, 1);
} fentry_readings SEC(".maps");

/* accumulated readings */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct bpf_perf_event_value));
	__uint(max_entries, 1);
} accum_readings SEC(".maps");

const volatile __u32 num_cpu = 1;

SEC("fentry/XXX")
int BPF_PROG(fentry_XXX)
{
	__u32 key = bpf_get_smp_processor_id();
	struct profile_reading *ptr;
	__u32 zero = 0;
	long err;

	/* look up before reading, to reduce error */
	ptr = bpf_map_lookup_elem(&fentry_readings, &zero);
	if (!ptr)
		return 0;

	ptr->armed = false;
	err = bpf_perf_event_read_value(&events, key, &ptr->value,
					sizeof(ptr->value));
	if (err)
		return 0;
	ptr->armed = true;

	return 0;
}

static inline void
fexit_update_maps(struct bpf_perf_event_value *after)
{
	struct profile_reading *before;
	struct bpf_perf_event_value diff;
	__u32 zero = 0;

	before = bpf_map_lookup_elem(&fentry_readings, &zero);
	/* only account samples with a valid fentry_reading */
	if (before && before->armed) {
		struct bpf_perf_event_value *accum;

		before->armed = false;
		diff.counter = after->counter - before->value.counter;
		diff.enabled = after->enabled - before->value.enabled;
		diff.running = after->running - before->value.running;

		accum = bpf_map_lookup_elem(&accum_readings, &zero);
		if (accum) {
			accum->counter += diff.counter;
			accum->enabled += diff.enabled;
			accum->running += diff.running;
		}
	}
}

SEC("fexit/XXX")
int BPF_PROG(fexit_XXX)
{
	struct bpf_perf_event_value reading;
	__u32 cpu = bpf_get_smp_processor_id();
	int err;

	/* read all events before updating the maps, to reduce error */
	err = bpf_perf_event_read_value(&events, cpu, &reading, sizeof(reading));
	if (err)
		return 0;

	fexit_update_maps(&reading);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
