// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include "bpf_experimental.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define CLOCK_MONOTONIC_ID	1
#define PAGE_SIZE		4096UL
/*
 * One reclaim round targets RECLAIM_MAX_ITER batches of RECLAIM_SIZE
 * each. Each bpf_wq callback reclaims a single batch and requeues the
 * same work item for the next one, so no callback runs longer than one
 * bounded reclaim pass.
 */
#define RECLAIM_SIZE		(32 * PAGE_SIZE)
#define RECLAIM_MAX_ITER	32

struct bpf_args {
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

/*
 * Statistics exposed to userspace through .bss, so the test can verify
 * that reclaim actually happened instead of relying on timing alone.
 */
u64 reclaim_calls;
u64 reclaimed_bytes;
/*
 * Reclaim attempts skipped because the target cgroup is dying or has
 * been removed. reclaim_skipped_dying counts lookups that still found
 * the cgroup while it is being torn down, reclaim_target_gone counts
 * lookups that found nothing. The test removes the target cgroup while
 * reclaim is running and checks that reclaim stops via these counters.
 */
u64 reclaim_skipped_dying;
u64 reclaim_target_gone;

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
	*val = bpf_mem_cgroup_page_state(cm.memcg,
		bpf_core_enum_value(enum node_stat_item,
				    WORKINGSET_REFAULT_FILE));
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

/*
 * A cgroup is dying once it has been offlined (CSS_ONLINE cleared) or
 * CSS_DYING has been raised, mirroring cgroup_is_dead()/css_is_dying()
 * in include/linux/cgroup.h. bpf_cgroup_from_id() can still hand back
 * such a cgroup, because it only fails once the last reference has been
 * dropped, so reclaim has to check these flags instead of relying on
 * the lookup failing.
 *
 * CSS_ONLINE and CSS_DYING come from vmlinux.h: the kernel defines them
 * in an anonymous enum, so bpf_core_enum_value() has no enum type to
 * bind to, and redeclaring them locally would clash with the vmlinux.h
 * enumerators. vmlinux.h is generated from the running kernel's BTF, so
 * the values already match the target kernel.
 */
static bool cgroup_is_dying(struct cgroup *cgrp)
{
	unsigned int flags = cgrp->self.flags;

	return (flags & CSS_DYING) || !(flags & CSS_ONLINE);
}

/*
 * Reclaim one batch from the target cgroup. Returns the number of
 * bytes reclaimed, or 0 if the cgroup is dying or gone or nothing was
 * reclaimed.
 */
static u64 reclaim_cgroup(u64 cgroup_id, u64 size)
{
	struct cgroup_memcg cm;
	u64 nr = 0;

	if (get_cgroup_memcg_from_id(cgroup_id, &cm)) {
		reclaim_target_gone++;
		return 0;
	}

	if (cgroup_is_dying(cm.cgrp)) {
		reclaim_skipped_dying++;
		put_cgroup_memcg(&cm);
		return 0;
	}

	reclaim_calls++;
	nr = bpf_proactive_reclaim(cm.memcg, size);
	reclaimed_bytes += nr;

	put_cgroup_memcg(&cm);

	return nr;
}

struct wq_elem {
	struct bpf_timer timer;
	struct bpf_wq work;
	u64 prev_event;
	u64 event_delta_threshold;
	u64 check_ns;
	/*
	 * Bytes still to reclaim in the current round, carried across
	 * requeues. 0 means no round is in progress; the timer path
	 * starts a new round by resetting it, requeued work only looks
	 * at it.
	 */
	u64 remaining;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct wq_elem);
} wq_map SEC(".maps");

static int reclaim_work_fn(void *map, int *key, void *value)
{
	struct wq_elem *elem = value;
	u64 nr, size;

	if (!elem->remaining) {
		/*
		 * Timer-triggered entry: start a new round only when the
		 * high cgroup refaults enough. Requeued entries skip this
		 * check and only look at remaining, so the refault delta
		 * is consumed once per round.
		 */
		if (!should_reclaim_cgroup(wq_high_cgroup_id, &elem->prev_event,
			elem->event_delta_threshold))
			return 0;
		elem->remaining = RECLAIM_MAX_ITER * RECLAIM_SIZE;
	}

	/* One bounded reclaim pass per callback */
	size = elem->remaining < RECLAIM_SIZE ? elem->remaining : RECLAIM_SIZE;
	nr = reclaim_cgroup(wq_low_cgroup_id, size);
	if (!nr) {
		elem->remaining = 0;
		return 0;
	}

	/* try_to_free_mem_cgroup_pages() may reclaim more than requested */
	if (nr >= elem->remaining)
		elem->remaining = 0;
	else
		elem->remaining -= nr;

	/* Requeue the same work item for the next batch */
	if (elem->remaining)
		bpf_wq_start(&elem->work, 0);

	return 0;
}

static int wq_timer_cb(void *map, int *key, struct wq_elem *elem)
{
	bpf_wq_start(&elem->work, 0);
	bpf_timer_start(&elem->timer, elem->check_ns, 0);

	return 0;
}

SEC("syscall")
int wq_prog_init(struct bpf_args *ctx)
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

	ret = bpf_wq_set_callback(&elem->work, reclaim_work_fn, 0);
	if (ret)
		return ret;

	ret = bpf_timer_init(&elem->timer, &wq_map, CLOCK_MONOTONIC_ID);
	if (ret)
		return ret;

	ret = bpf_timer_set_callback(&elem->timer, wq_timer_cb);
	if (ret)
		return ret;

	elem->prev_event = 0;
	elem->remaining = 0;
	elem->event_delta_threshold = ctx->event_delta_threshold;
	elem->check_ns = ctx->check_ns;

	wq_high_cgroup_id = ctx->high_cgroup_id;
	wq_low_cgroup_id = ctx->low_cgroup_id;

	return bpf_timer_start(&elem->timer, elem->check_ns, 0);
}

char _license[] SEC("license") = "GPL";
