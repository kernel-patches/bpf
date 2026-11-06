// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <errno.h>
#include <bpf/bpf_helpers.h>

#define CLOCK_MONOTONIC 1
#define TIMER_NSEC (60ULL * 1000 * 1000 * 1000)
#define LIVE_TIMER_NSEC 1000ULL

struct timer_value {
	struct bpf_timer timer;
	u64 data;
};

struct {
	__uint(type, BPF_MAP_TYPE_RHASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 1);
	__type(key, u64);
	__type(value, struct timer_value);
} timer_map SEC(".maps");

u64 live_armed;
u64 live_cancelled;
u64 live_cb_cnt;
long timer_init_err;
long live_init_err;
long live_set_callback_err;
long live_start_err;
long live_cancel_err;

static int timer_cb(void *map, u64 *key, struct timer_value *value)
{
	__sync_fetch_and_add(&live_cb_cnt, 1);
	return 0;
}

/* Initialize through a retained pointer after deleting the element. */
static long arm_timer_cb(struct bpf_map *map, u64 *key,
			 struct timer_value *value, void *ctx)
{
	u64 key_copy = *key;
	long err;

	err = bpf_map_delete_elem(map, &key_copy);
	if (err)
		return 1;

	err = bpf_timer_init(&value->timer, map, CLOCK_MONOTONIC);
	timer_init_err = err;
	/* Do not configure or start the deleted value, even on an unfixed kernel. */
	return 1;
}

SEC("syscall")
int arm_deleted_timer(void *ctx)
{
	bpf_for_each_map_elem(&timer_map, arm_timer_cb, NULL, 0);
	return 0;
}

/* Arm a live timer; the host waits for its callback before cancellation. */
SEC("syscall")
int live_arm_timer(void *ctx)
{
	struct timer_value *v;
	u64 key = 0;
	long err;

	v = bpf_map_lookup_elem(&timer_map, &key);
	if (!v)
		return -EINVAL;

	err = bpf_timer_init(&v->timer, &timer_map, CLOCK_MONOTONIC);
	if (err) {
		live_init_err = err;
		return err;
	}

	err = bpf_timer_set_callback(&v->timer, timer_cb);
	if (err) {
		live_set_callback_err = err;
		return err;
	}

	err = bpf_timer_start(&v->timer, LIVE_TIMER_NSEC, 0);
	if (err) {
		live_start_err = err;
		return err;
	}

	__sync_fetch_and_add(&live_armed, 1);
	return 0;
}

SEC("syscall")
int cancel_live_timer(void *ctx)
{
	struct timer_value *v;
	u64 key = 0;
	long err;

	v = bpf_map_lookup_elem(&timer_map, &key);
	if (!v)
		return -EINVAL;

	err = bpf_timer_cancel(&v->timer);
	if (err < 0) {
		live_cancel_err = err;
		return err;
	}

	__sync_fetch_and_add(&live_cancelled, 1);
	return 0;
}

char _license[] SEC("license") = "GPL";
