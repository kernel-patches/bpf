// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_tcp_helpers.h"

char _license[] SEC("license") = "GPL";
struct map_elem {
	int counter;
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1000);
	__type(key, int);
	__type(value, struct map_elem);
} hmap SEC(".maps");

__u64 bss_data;
struct bpf_timer global_timer;

__u64 callback_check = 52;

static int timer_cb1(void *map, int *key, __u64 *data)
{
	/* increment the same bss variable twice */
	bss_data += 5;
	data[0] += 10; /* &data[1] == &bss_data */
	/* note data[1] access will be rejected by the verifier,
	 * since &data[1] points to the &global_timer.
	 */

	/* rearm self to be called again in ~35 seconds */
	bpf_timer_start(&global_timer, 1ull << 35);
	return 0;
}

SEC("fentry/bpf_fentry_test1")
int BPF_PROG(test1, int a)
{
	bpf_timer_init(&global_timer, timer_cb1, 0);
	bpf_timer_start(&global_timer, 0 /* call timer_cb1 asap */);
	return 0;
}

static int timer_cb2(void *map, int *key, struct map_elem *val)
{
	callback_check--;
	if (--val->counter)
		/* re-arm the timer again to execute after 1 msec */
		bpf_timer_start(&val->timer, 1000);
	else {
		/* cancel global_timer otherwise bpf_fentry_test1 prog
		 * will stay alive forever.
		 */
		bpf_timer_cancel(&global_timer);
		bpf_timer_cancel(&val->timer);
	}
	return 0;
}

int bpf_timer_test(void)
{
	struct map_elem *val;
	int key = 0;

	val = bpf_map_lookup_elem(&hmap, &key);
	if (val) {
		bpf_timer_init(&val->timer, timer_cb2, 0);
		bpf_timer_start(&val->timer, 1000);
	}
	return 0;
}

SEC("fentry/bpf_fentry_test2")
int BPF_PROG(test2, int a, int b)
{
	struct map_elem val = {};
	int key = 0;

	val.counter = 10; /* number of times to trigger timer_cb1 */
	bpf_map_update_elem(&hmap, &key, &val, 0);
	return bpf_timer_test();
}
