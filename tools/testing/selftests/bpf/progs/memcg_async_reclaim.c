// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include "bpf_experimental.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define CLOCK_MONOTONIC_ID	1
#define PAGE_SIZE		4096UL
#define RECLAIM_SIZE		(32 * PAGE_SIZE)
#define RECLAIM_MAX_ITER	32

struct bpf_args_s {
	u64 high_cgroup_id;
	u64 low_cgroup_id;
	u64 event_delta_threshold;
	u64 check_ns;
};

struct cgroup_memcg {
	struct cgroup *cgrp;
	struct mem_cgroup *memcg;
};

static u64 wq_high_cgroup_id;
static u64 wq_low_cgroup_id;

static int get_cgroup_memcg_from_id(u64 cgroup_id, struct cgroup_memcg *cm)
{
	cm->cgrp = bpf_cgroup_from_id(cgroup_id);
	if (!cm->cgrp)
		return -1;

	cm->memcg = bpf_get_mem_cgroup(&cm->cgrp->self);
	if (!cm->memcg) {
		bpf_cgroup_release(cm->cgrp);
		return -1;
	}

	return 0;
}

static void put_cgroup_memcg(struct cgroup_memcg *cm)
{
	bpf_put_mem_cgroup(cm->memcg);
	bpf_cgroup_release(cm->cgrp);
}

static int get_cgroup_event(u64 cgroup_id, u64 *val)
{
	struct cgroup_memcg cm;

	if (get_cgroup_memcg_from_id(cgroup_id, &cm))
		return -1;
	bpf_mem_cgroup_flush_stats(cm.memcg);
	*val = bpf_mem_cgroup_page_state(cm.memcg, WORKINGSET_REFAULT_FILE);
	put_cgroup_memcg(&cm);

	return 0;
}

static bool
should_reclaim_cgroup(u64 cgroup_id, u64 *prev_event, u64 event_delta_threshold)
{
	u64 cur, delta;

	if (get_cgroup_event(cgroup_id, &cur))
		return false;

	delta = cur - *prev_event;
	*prev_event = cur;

	return delta >= event_delta_threshold;
}

static int reclaim_cgroup(u64 cgroup_id)
{
	struct cgroup_memcg cm;
	int i;

	if (get_cgroup_memcg_from_id(cgroup_id, &cm))
		return 0;

	for (i = 0; i < RECLAIM_MAX_ITER; i++) {
		if (!bpf_proactive_reclaim(cm.memcg, RECLAIM_SIZE))
			break;
	}

	put_cgroup_memcg(&cm);

	return 0;
}

struct wq_elem {
	struct bpf_timer timer;
	struct bpf_wq work;
	u64 prev_event;
	u64 event_delta_threshold;
	u64 check_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct wq_elem);
} wq_map SEC(".maps");

static int async_free(void *map, int *key, void *value)
{
	struct wq_elem *elem = value;

	if (should_reclaim_cgroup(wq_high_cgroup_id, &elem->prev_event,
		elem->event_delta_threshold)) {
		reclaim_cgroup(wq_low_cgroup_id);
		bpf_wq_start(&elem->work, 0);
	}

	return 0;
}

static int wq_timer_cb(void *map, int *key, struct wq_elem *elem)
{
	bpf_wq_start(&elem->work, 0);
	bpf_timer_start(&elem->timer, elem->check_ns, 0);

	return 0;
}

SEC("syscall")
int wq_prog_init(struct bpf_args_s *ctx)
{
	struct wq_elem *elem;
	__u32 key = 0;
	int ret;

	elem = bpf_map_lookup_elem(&wq_map, &key);
	if (!elem)
		return -1;

	ret = bpf_wq_init(&elem->work, &wq_map, 0);
	if (ret)
		return ret;

	ret = bpf_wq_set_callback(&elem->work, async_free, 0);
	if (ret)
		return ret;

	ret = bpf_timer_init(&elem->timer, &wq_map, CLOCK_MONOTONIC_ID);
	if (ret)
		return ret;

	ret = bpf_timer_set_callback(&elem->timer, wq_timer_cb);
	if (ret)
		return ret;

	elem->prev_event = 0;
	elem->event_delta_threshold = ctx->event_delta_threshold;
	elem->check_ns = ctx->check_ns;

	wq_high_cgroup_id = ctx->high_cgroup_id;
	wq_low_cgroup_id = ctx->low_cgroup_id;

	return bpf_timer_start(&elem->timer, elem->check_ns, 0);
}

char LICENSE[] SEC("license") = "GPL";
