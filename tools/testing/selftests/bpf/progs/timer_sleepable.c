// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook
 * Copyright (c) 2024 Benjamin Tissoires
 */

#include "bpf_experimental.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "../bpf_testmod/bpf_testmod_kfunc.h"

char _license[] SEC("license") = "GPL";

#define CLOCK_MONOTONIC 1

struct elem {
	struct bpf_timer t;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 3);
	__type(key, int);
	__type(value, struct elem);
} timer_map SEC(".maps");

__u32 ok_sleepable;

/* callback for sleepable timer */
static int timer_cb_sleepable(void *map, int *key, struct bpf_timer *timer)
{
	bpf_kfunc_call_test_sleepable();
	ok_sleepable |= (1 << *key);
	return 0;
}

SEC("syscall")
/* check that calling bpf_timer_start() with BPF_F_TIMER_SLEEPABLE on a sleepable
 * callback works
 */
__retval(0)
long test_call_sleepable(void *ctx)
{
	int key = 0;
	struct bpf_timer *timer;

	if (ok_sleepable & 1)
		return -1;

	timer = bpf_map_lookup_elem(&timer_map, &key);
	if (timer) {
		if (bpf_timer_init(timer, &timer_map, CLOCK_MONOTONIC) != 0)
			return -2;
		bpf_timer_set_sleepable_cb(timer, timer_cb_sleepable);
		if (bpf_timer_start(timer, 0, BPF_F_TIMER_SLEEPABLE))
			return -3;
	} else {
		return -4;
	}

	return 0;
}

SEC("?syscall")
__log_level(2)
__failure
/* check that bpf_timer_set_callback() can not be called with a
 * sleepable callback
 */
__msg("mark_precise: frame0: regs=r1 stack= before")
__msg(": (85) call bpf_kfunc_call_test_sleepable#") /* anchor message */
__msg("program must be sleepable to call sleepable kfunc bpf_kfunc_call_test_sleepable")
long test_non_sleepable_sleepable_callback(void *ctx)
{
	int key = 0;
	struct bpf_timer *timer;

	timer = bpf_map_lookup_elem(&timer_map, &key);
	if (timer) {
		bpf_timer_init(timer, &timer_map, CLOCK_MONOTONIC);
		bpf_timer_set_callback(timer, timer_cb_sleepable);
		bpf_timer_start(timer, 0, BPF_F_TIMER_SLEEPABLE);
	}

	return 0;
}

SEC("syscall")
/* check that calling bpf_timer_start() without BPF_F_TIMER_SLEEPABLE on a sleepable
 * callback is returning -EINVAL
 */
__retval(-22)
long test_call_sleepable_missing_flag(void *ctx)
{
	int key = 1;
	struct bpf_timer *timer;

	timer = bpf_map_lookup_elem(&timer_map, &key);
	if (!timer)
		return 1;

	if (bpf_timer_init(timer, &timer_map, CLOCK_MONOTONIC))
		return 2;

	if (bpf_timer_set_sleepable_cb(timer, timer_cb_sleepable))
		return 3;

	return bpf_timer_start(timer, 0, 0);
}

SEC("syscall")
/* check that calling bpf_timer_start() without BPF_F_TIMER_SLEEPABLE on a sleepable
 * callback is returning -EINVAL
 */
__retval(-22)
long test_call_sleepable_delay(void *ctx)
{
	int key = 2;
	struct bpf_timer *timer;

	timer = bpf_map_lookup_elem(&timer_map, &key);
	if (!timer)
		return 1;

	if (bpf_timer_init(timer, &timer_map, CLOCK_MONOTONIC))
		return 2;

	if (bpf_timer_set_sleepable_cb(timer, timer_cb_sleepable))
		return 3;

	return bpf_timer_start(timer, 1, BPF_F_TIMER_SLEEPABLE);
}

SEC("?syscall")
__log_level(2)
__failure
/* check that the first argument of bpf_timer_set_callback()
 * is a correct bpf_timer pointer.
 */
__msg("mark_precise: frame0: regs=r1 stack= before")
__msg(": (85) call bpf_timer_set_sleepable_cb_impl#") /* anchor message */
__msg("arg#0 doesn't point to a map value")
long test_wrong_pointer(void *ctx)
{
	int key = 0;
	struct bpf_timer *timer;

	timer = bpf_map_lookup_elem(&timer_map, &key);
	if (!timer)
		return 1;

	if (bpf_timer_init(timer, &timer_map, CLOCK_MONOTONIC))
		return 2;

	if (bpf_timer_set_sleepable_cb((void *)&timer, timer_cb_sleepable))
		return 3;

	return -22;
}

SEC("?syscall")
__log_level(2)
__failure
/* check that the first argument of bpf_timer_set_callback()
 * is a correct bpf_timer pointer.
 */
__msg("mark_precise: frame0: regs=r1 stack= before")
__msg(": (85) call bpf_timer_set_sleepable_cb_impl#") /* anchor message */
__msg("arg#0 offset can not be greater than 0")
long test_wrong_pointer_offset(void *ctx)
{
	int key = 0;
	struct bpf_timer *timer;

	timer = bpf_map_lookup_elem(&timer_map, &key);
	if (!timer)
		return 1;

	if (bpf_timer_init(timer, &timer_map, CLOCK_MONOTONIC))
		return 2;

	if (bpf_timer_set_sleepable_cb((void *)timer + 1, timer_cb_sleepable))
		return 3;

	return -22;
}
