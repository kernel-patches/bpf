// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_experimental.h"

char _license[] SEC("license") = "GPL";

#define CLOCK_MONOTONIC 1

struct elem {
	struct bpf_timer t;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct elem);
} timers SEC(".maps");

int zero, spun, cb_cnt, cb_done;

static __noinline int spins(void)
{
	int cnt = zero;

	for (;;) {
		cond_break;
		cnt++;
	}
	return cnt;
}

static __noinline int counts_to_1000(void)
{
	int i, cnt = zero;

	for (i = zero; i < 1000; i++) {
		cond_break;
		cnt++;
	}
	return cnt;
}

static int timer_cb(void *map, int *key, struct elem *e)
{
	cb_cnt = counts_to_1000();
	cb_done = 1;
	return 0;
}

/*
 * The time slice of this run is used up when the timer is started. The callback is another
 * run on the same cpu, with a time slice of its own.
 */
SEC("tc")
int timer_after_timeout(void *ctx)
{
	struct elem *e;
	int key = 0;

	e = bpf_map_lookup_elem(&timers, &key);
	if (!e)
		return 1;
	if (bpf_timer_init(&e->t, &timers, CLOCK_MONOTONIC))
		return 2;
	if (bpf_timer_set_callback(&e->t, timer_cb))
		return 3;
	spun = spins();
	if (bpf_timer_start(&e->t, 0, BPF_F_TIMER_CPU_PIN))
		return 4;
	return 0;
}
