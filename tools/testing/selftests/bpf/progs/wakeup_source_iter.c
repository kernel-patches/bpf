// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Google LLC */
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#define NSEC_PER_MS 1000000UL
#define WAKEUP_SOURCE_NAME_LEN 32

char _license[] SEC("license") = "GPL";

SEC("iter/wakeup_source")
int wakeup_source_collector(struct bpf_iter__wakeup_source *ctx)
{
	const struct wakeup_source *ws = ctx->wakeup_source;
	struct seq_file *seq = ctx->meta->seq;
	char name[WAKEUP_SOURCE_NAME_LEN] = {'\0'};
	const char *pname;
	bool active, autosleep_enable;
	u64 active_count, event_count, expire_count, wakeup_count;
	s64 active_time, curr_time, last_change_time, max_time,
	    prevent_sleep_time, start_prevent_time, total_time;

	if (!ws)
		return 0;

	active = BPF_CORE_READ_BITFIELD_PROBED(ws, active);
	autosleep_enable = BPF_CORE_READ_BITFIELD_PROBED(ws, autosleep_enabled);
	if (bpf_core_read(&pname, sizeof(pname), &ws->name) ||
	    bpf_probe_read_kernel_str(name, sizeof(name), pname) < 0 ||
	    bpf_core_read(&active_count, sizeof(active_count), &ws->active_count) ||
	    bpf_core_read(&event_count, sizeof(event_count), &ws->event_count) ||
	    bpf_core_read(&expire_count, sizeof(expire_count), &ws->expire_count) ||
	    bpf_core_read(&last_change_time, sizeof(last_change_time), &ws->last_time) ||
	    bpf_core_read(&max_time, sizeof(max_time), &ws->max_time) ||
	    bpf_core_read(
		&prevent_sleep_time, sizeof(prevent_sleep_time), &ws->prevent_sleep_time) ||
	    bpf_core_read(
		&start_prevent_time, sizeof(start_prevent_time), &ws->start_prevent_time) ||
	    bpf_core_read(&total_time, sizeof(total_time), &ws->total_time) ||
	    bpf_core_read(&wakeup_count, sizeof(wakeup_count), &ws->wakeup_count))
		return 0;


	curr_time = bpf_ktime_get_ns();
	active_time = 0;
	if (active) {
		active_time = curr_time - last_change_time;
		total_time += active_time;
		if (active_time > max_time)
			max_time = active_time;
		if (autosleep_enable)
			prevent_sleep_time += curr_time - start_prevent_time;

	}

	BPF_SEQ_PRINTF(seq,
		       "%s %lu %ld %lu %lu %ld %ld %ld %ld %lu\n",
		       name,
		       active_count,
		       active_time / NSEC_PER_MS,
		       event_count,
		       expire_count,
		       last_change_time / NSEC_PER_MS,
		       max_time / NSEC_PER_MS,
		       prevent_sleep_time / NSEC_PER_MS,
		       total_time / NSEC_PER_MS,
		       wakeup_count);
	return 0;
}
