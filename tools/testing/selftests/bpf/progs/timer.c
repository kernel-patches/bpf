// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_tcp_helpers.h"

char _license[] SEC("license") = "GPL";
struct map_elem {
	struct bpf_timer timer;
	int counter;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1000);
	__type(key, int);
	__type(value, struct map_elem);
} hmap SEC(".maps");

__u64 callback_check = 52;

static int timer_cb(struct bpf_map *map, int *key, struct map_elem *val)
{
	callback_check--;
	if (--val->counter)
		/* re-arm the timer again to execute after 1 msec */
		bpf_timer_mod(&val->timer, 1);
	return 0;
}

int bpf_timer_test(void)
{
	struct map_elem *val;
	int key = 0;

	val = bpf_map_lookup_elem(&hmap, &key);
	if (val) {
		bpf_timer_init(&val->timer, timer_cb, 0);
		bpf_timer_mod(&val->timer, 1);
	}
	return 0;
}

SEC("fentry/bpf_fentry_test1")
int BPF_PROG(test1, int a)
{
	struct map_elem val = {};
	int key = 0;

	val.counter = 10, /* number of times to trigger timer_cb */
	bpf_map_update_elem(&hmap, &key, &val, 0);
	return bpf_timer_test();
}
