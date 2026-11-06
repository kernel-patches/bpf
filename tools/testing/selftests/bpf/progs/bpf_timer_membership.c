// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 KylinSoft Corporation. */

/* Run one command per test_run; stale-pointer commands only record init. */

#include <vmlinux.h>
#include <errno.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

#define CB_SLOTS 64
#define CLOCK_MONOTONIC 1
#define TIMER_NS 1000000ULL

struct timer_value {
	struct bpf_timer timer;
	__u64 cookie;
};

enum timer_cmd {
	CMD_INIT_START = 1,
	CMD_DELETE_INIT,
	CMD_REPLACE_INIT,
};

/* Results reset before each command. */
int res_lookup_err;
int res_delete_err;
int res_update_err;
int res_init_err;
int res_new_init_err;
int res_set_err;
int res_start_err;
__u64 res_old_addr;
__u64 res_new_addr;
u32 cmd;
u64 cookie;
u64 cb_count[CB_SLOTS];

static __always_inline void reset_result(void)
{
	res_lookup_err = 0;
	res_delete_err = 0;
	res_update_err = 0;
	res_init_err = 0;
	res_new_init_err = 0;
	res_set_err = 0;
	res_start_err = 0;
	res_old_addr = 0;
	res_new_addr = 0;
}

/* Configure and start only a current map member. */
#define TIMER_INIT_START(v, map_sym, cb)				\
	({								\
		long __e;						\
		(v)->cookie = cookie;					\
		__e = bpf_timer_init(&(v)->timer, &map_sym, CLOCK_MONOTONIC); \
		if (!__e) {						\
			res_set_err = bpf_timer_set_callback(&(v)->timer, cb); \
			if (!res_set_err)				\
				res_start_err = bpf_timer_start(&(v)->timer, \
								TIMER_NS, 0); \
		}							\
		__e;							\
	})

/* Delete and initialize through the retained pointer in one RCU section.
 * Never configure or start a timer through that pointer, even if init succeeds.
 */
#define TIMER_DELETE_INIT(map_sym, v)					\
	({								\
		long __e;						\
		bpf_rcu_read_lock();					\
		res_delete_err = bpf_map_delete_elem(&map_sym, &key);	\
		__e = res_delete_err;					\
		if (!__e)						\
			res_init_err = bpf_timer_init(&(v)->timer, &map_sym, \
						      CLOCK_MONOTONIC);	\
		bpf_rcu_read_unlock();					\
		__e;							\
	})

#define DEFINE_TIMER_MAP(map_sym, value_type)				\
static int map_sym##_cb(void *map, int *key, void *value)		\
{									\
	value_type *v = value;						\
									\
	__sync_fetch_and_add(&cb_count[v->cookie & (CB_SLOTS - 1)], 1);	\
	return 0;							\
}									\
									\
SEC("syscall")								\
int map_sym##_run(void *ctx)						\
{									\
	value_type *v, *nv, zero = {};					\
	int key = 0;							\
									\
	reset_result();							\
									\
	switch (cmd) {							\
	case CMD_INIT_START:						\
		v = bpf_map_lookup_elem(&map_sym, &key);		\
		if (!v) {						\
			res_lookup_err = -ENOENT;			\
			break;						\
		}							\
		res_old_addr = (__u64)v;				\
		res_init_err = TIMER_INIT_START(v, map_sym, map_sym##_cb); \
		break;							\
	case CMD_DELETE_INIT:						\
		v = bpf_map_lookup_elem(&map_sym, &key);		\
		if (!v) {						\
			res_lookup_err = -ENOENT;			\
			break;						\
		}							\
		res_old_addr = (__u64)v;				\
		TIMER_DELETE_INIT(map_sym, v);				\
		break;							\
	case CMD_REPLACE_INIT:						\
		v = bpf_map_lookup_elem(&map_sym, &key);		\
		if (!v) {						\
			res_lookup_err = -ENOENT;			\
			break;						\
		}							\
		res_old_addr = (__u64)v;				\
		bpf_rcu_read_lock();					\
		res_update_err = bpf_map_update_elem(&map_sym, &key, &zero, 0); \
		if (res_update_err) {					\
			bpf_rcu_read_unlock();				\
			break;						\
		}							\
		nv = bpf_map_lookup_elem(&map_sym, &key);		\
		if (!nv) {						\
			res_lookup_err = -ENOENT;			\
			bpf_rcu_read_unlock();				\
			break;						\
		}							\
		res_new_addr = (__u64)nv;				\
		res_init_err = bpf_timer_init(&v->timer, &map_sym,	\
					      CLOCK_MONOTONIC);		\
		bpf_rcu_read_unlock();					\
		res_new_init_err = TIMER_INIT_START(nv, map_sym, map_sym##_cb); \
		break;							\
	default:							\
		res_lookup_err = -EINVAL;				\
		break;							\
	}								\
	return 0;							\
}

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 4);
	__type(key, int);
	__type(value, struct timer_value);
} values SEC(".maps");

DEFINE_TIMER_MAP(values, struct timer_value)
