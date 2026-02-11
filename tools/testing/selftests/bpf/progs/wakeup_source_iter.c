// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Google LLC */
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
	s64 active_time, curr_time, max_time, prevent_sleep_time, total_time;

	if (!ws)
		return 0;

	active = BPF_CORE_READ_BITFIELD_PROBED(ws, active);
	autosleep_enable = BPF_CORE_READ_BITFIELD_PROBED(ws, autosleep_enabled);
	if (bpf_core_read(&pname, sizeof(pname), &ws->name) ||
	    bpf_probe_read_kernel_str(name, sizeof(name), pname) < 0)
		return 0;

	active_time = 0;
	curr_time = bpf_ktime_get_ns();
	max_time = ws->max_time;
	prevent_sleep_time = ws->prevent_sleep_time;
	total_time = ws->total_time;

	if (active) {
		active_time = curr_time - ws->last_time;
		total_time += active_time;
		if (active_time > max_time)
			max_time = active_time;
		if (autosleep_enable)
			prevent_sleep_time +=
				curr_time - ws->start_prevent_time;
	}

	BPF_SEQ_PRINTF(seq,
		       "%s %lu %ld %lu %lu %ld %ld %ld %ld %lu\n",
		       name,
		       ws->active_count,
		       active_time / NSEC_PER_MS,
		       ws->event_count,
		       ws->expire_count,
		       ws->last_time / NSEC_PER_MS,
		       max_time / NSEC_PER_MS,
		       prevent_sleep_time / NSEC_PER_MS,
		       total_time / NSEC_PER_MS,
		       ws->wakeup_count);
	return 0;
}
