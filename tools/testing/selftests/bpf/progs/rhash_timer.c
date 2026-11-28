// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <errno.h>
#include <bpf/bpf_helpers.h>

#define CLOCK_MONOTONIC 1

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

u64 initialized;
u64 cancelled;
long timer_init_err;
long timer_set_callback_err;
long timer_cancel_err;

static int timer_cb(void *map, u64 *key, struct timer_value *value)
{
	return 0;
}

static long init_timer_cb(struct bpf_map *map, u64 *key,
			  struct timer_value *value, void *ctx)
{
	u64 key_copy = *key;
	long err;

	err = bpf_map_delete_elem(map, &key_copy);
	if (err)
		return 1;

	err = bpf_timer_init(&value->timer, map, CLOCK_MONOTONIC);
	if (err) {
		timer_init_err = err;
		return 1;
	}

	timer_set_callback_err = bpf_timer_set_callback(&value->timer, timer_cb);

	__sync_fetch_and_add(&initialized, 1);
	return 1;
}

static long cancel_timer_cb(struct bpf_map *map, u64 *key,
			    struct timer_value *value, void *ctx)
{
	long err;

	err = bpf_timer_cancel(&value->timer);
	if (err == -EINVAL)
		return 1;
	if (err < 0) {
		timer_cancel_err = err;
		return 1;
	}

	__sync_fetch_and_add(&cancelled, 1);
	return 1;
}

SEC("syscall")
int init_deleted_timer(void *ctx)
{
	bpf_for_each_map_elem(&timer_map, init_timer_cb, NULL, 0);
	return 0;
}

SEC("syscall")
int cancel_recycled_timer(void *ctx)
{
	bpf_for_each_map_elem(&timer_map, cancel_timer_cb, NULL, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
