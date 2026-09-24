// SPDX-License-Identifier: GPL-2.0
/*
 * Refault-driven asynchronous proactive reclaim.
 *
 * A bpf_timer ticks every cfg->interval_ns. On each tick a bpf_wq callback
 * checks whether the monitored cgroup refaulted enough to warrant reclaim; if
 * so it opens a round of up to cfg->max_batches batches and reclaims one batch
 * of cfg->batch_bytes per callback, requeueing itself until the round's budget
 * is spent. Nothing here blocks the monitored workload: the reclaim happens on
 * a workqueue, against a different cgroup.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "memcg_async_reclaim.h"

#define CLOCK_MONOTONIC		1

struct cgroup_memcg {
	struct cgroup *cgrp;
	struct mem_cgroup *memcg;
};

static u64 wq_monitor_cgroup_id;
static u64 wq_target_cgroup_id;

/*
 * Statistics exposed to userspace through .bss, so that the loader can report
 * what actually happened instead of inferring it from timings.
 *
 * These are __u64 rather than u64 because bpftool emits the type name verbatim
 * into the generated skeleton, and the loader has no kernel typedefs.
 */
__u64 reclaim_calls;
__u64 reclaimed_bytes;

/*
 * Number of rounds started, i.e. ticks on which the monitored cgroup crossed
 * the refault threshold. A round spans up to max_batches callbacks, so this
 * tells the two apart: many calls per round means the target had a lot to
 * give, many rounds means the monitor keeps refaulting.
 */
__u64 reclaim_rounds;

/*
 * A timer that fails to rearm stops the whole chain, which from userspace looks
 * exactly like "nothing needed reclaiming". Count it so the two can be told
 * apart instead of blaming the workload.
 */
__u64 timer_failures;

/*
 * bpf_proactive_reclaim() reports failure as a negative return, which is
 * otherwise indistinguishable from "this cgroup has nothing left to reclaim".
 * Keep the last one so a failing kfunc is not mistaken for an idle cgroup.
 * Stored as a positive errno.
 */
__u64 last_reclaim_err;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 16);
} reclaim_events SEC(".maps");

/*
 * Reports are best effort: when the ringbuf is full, for example when
 * userspace does not consume the events, the report is dropped.
 */
static void emit_reclaim_event(enum reclaim_outcome outcome)
{
	struct reclaim_event *ev;

	ev = bpf_ringbuf_reserve(&reclaim_events, sizeof(*ev), 0);
	if (!ev)
		return;

	ev->outcome = outcome;
	bpf_ringbuf_submit(ev, 0);
}

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

/*
 * Total workingset refaults of a cgroup, across memory types.
 *
 * Pressure shows up in the counter matching the memory the workload uses: a
 * page-cache workload refaults file pages, an anonymous one refaults anon.
 * Watching only either counter makes the trigger blind to the other kind of
 * workload, so sum them; for a workload that stresses one type only, the
 * other term stays 0.
 */
static int get_cgroup_refaults(u64 cgroup_id, u64 *val)
{
	struct cgroup_memcg cm;

	if (get_cgroup_memcg_from_id(cgroup_id, &cm))
		return -1;
	bpf_mem_cgroup_flush_stats(cm.memcg);
	*val = bpf_mem_cgroup_page_state(cm.memcg,
		bpf_core_enum_value(enum node_stat_item,
				    WORKINGSET_REFAULT_FILE)) +
	       bpf_mem_cgroup_page_state(cm.memcg,
		bpf_core_enum_value(enum node_stat_item,
				    WORKINGSET_REFAULT_ANON));
	put_cgroup_memcg(&cm);

	return 0;
}

static bool
should_reclaim_cgroup(u64 cgroup_id, u64 *prev_refaults, u64 threshold)
{
	u64 cur, delta;

	if (get_cgroup_refaults(cgroup_id, &cur))
		return false;

	delta = cur - *prev_refaults;
	*prev_refaults = cur;

	return delta >= threshold;
}

/*
 * rmdir clears CSS_ONLINE on cgrp->self in cgroup_destroy_locked() and only
 * then deactivates the cgroup's kernfs node with kernfs_remove().
 * bpf_cgroup_from_id() resolves an id through
 * kernfs_find_and_get_node_by_id(), which refuses deactivated nodes, so the
 * lookup starts failing inside the rmdir syscall -- not, as one might expect,
 * once the cgroup's last reference has been dropped.
 *
 * The window in which the lookup still succeeds while the cgroup is already
 * dying is therefore just the few statements between those two. An attempt that
 * lands in it reports RECLAIM_OUTCOME_SKIPPED_DYING; after rmdir has returned,
 * every attempt reports TARGET_GONE instead. The check is kept because it is
 * the only thing standing between reclaim and a cgroup that is mid-teardown.
 *
 * Only CSS_ONLINE is worth testing. CSS_DYING is raised by kill_css_sync(),
 * which dereferences css->ss and so is never called with cgrp->self; the
 * cgroup's own css only ever loses CSS_ONLINE. This is therefore
 * cgroup_is_dead() from include/linux/cgroup.h, not css_is_dying().
 *
 * CSS_ONLINE comes from vmlinux.h: the kernel defines it in an anonymous enum,
 * so bpf_core_enum_value() has no enum type to bind to, and redeclaring it
 * locally would clash with the vmlinux.h enumerators. vmlinux.h is generated
 * from the running kernel's BTF, so the value already matches the target
 * kernel.
 */
static bool cgroup_is_dying(struct cgroup *cgrp)
{
	return !(cgrp->self.flags & CSS_ONLINE);
}

/*
 * Reclaim one batch from the target cgroup. Returns the number of bytes
 * reclaimed, or 0 if the cgroup is dying or gone, the kfunc failed, or nothing
 * was reclaimed. Each attempt reports its outcome through the reclaim_events
 * ringbuf, and a failing kfunc additionally records its errno in
 * last_reclaim_err.
 */
static u64 reclaim_cgroup(u64 cgroup_id, u64 size, int swappiness)
{
	struct cgroup_memcg cm;
	long nr;

	if (get_cgroup_memcg_from_id(cgroup_id, &cm)) {
		emit_reclaim_event(RECLAIM_OUTCOME_TARGET_GONE);
		return 0;
	}

	if (cgroup_is_dying(cm.cgrp)) {
		emit_reclaim_event(RECLAIM_OUTCOME_SKIPPED_DYING);
		put_cgroup_memcg(&cm);
		return 0;
	}

	reclaim_calls++;
	nr = bpf_proactive_reclaim(cm.memcg, size, swappiness);
	if (nr < 0)
		last_reclaim_err = -nr;
	else if (nr > 0)
		reclaimed_bytes += nr;
	emit_reclaim_event(RECLAIM_OUTCOME_CALLED);

	put_cgroup_memcg(&cm);

	return nr > 0 ? nr : 0;
}

struct wq_elem {
	struct bpf_timer timer;
	struct bpf_wq work;
	u64 prev_refaults;
	u64 refault_threshold;
	u64 check_ns;
	u64 batch_bytes;
	u64 max_batches;
	int swappiness;
	/*
	 * Bytes still to reclaim in the current round, carried across requeues.
	 * 0 means no round is in progress; the timer path starts a new round by
	 * resetting it, requeued work only looks at it.
	 */
	u64 remaining;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct wq_elem);
} wq_map SEC(".maps");

/*
 * batch_bytes is a byte count, not a page count: bpf_proactive_reclaim()
 * converts it against the running kernel's PAGE_SIZE and returns bytes, so the
 * configuration holds on any page size. The kfunc also clamps a batch to the
 * kernel's MEMCG_CHARGE_BATCH, which is not visible to BPF; a clamped batch
 * only means a round needs more callbacks, because remaining is decremented by
 * the bytes actually reclaimed.
 */
static int reclaim_work_fn(void *map, int *key, void *value)
{
	struct wq_elem *elem = value;
	u64 nr, size;

	if (!elem->remaining) {
		/*
		 * Timer-triggered entry: start a new round only when the
		 * monitored cgroup refaults enough. Requeued entries skip this
		 * check and only look at remaining, so a round consumes the
		 * refault delta only on the tick that starts it; ticks that find
		 * no round in progress consume and discard it.
		 */
		if (!should_reclaim_cgroup(wq_monitor_cgroup_id,
					   &elem->prev_refaults,
					   elem->refault_threshold))
			return 0;
		elem->remaining = elem->max_batches * elem->batch_bytes;
		reclaim_rounds++;
	}

	/* One bounded reclaim pass per callback */
	size = elem->remaining < elem->batch_bytes ? elem->remaining
						   : elem->batch_bytes;
	nr = reclaim_cgroup(wq_target_cgroup_id, size, elem->swappiness);
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
	/*
	 * A failed bpf_wq_start() self-heals on the next tick; a failed rearm
	 * does not, so only the latter is worth reporting.
	 */
	bpf_wq_start(&elem->work, 0);
	if (bpf_timer_start(&elem->timer, elem->check_ns, 0))
		timer_failures++;

	return 0;
}

SEC("syscall")
int reclaim_prog_init(struct reclaim_cfg *ctx)
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

	ret = bpf_timer_init(&elem->timer, &wq_map, CLOCK_MONOTONIC);
	if (ret)
		return ret;

	ret = bpf_timer_set_callback(&elem->timer, wq_timer_cb);
	if (ret)
		return ret;

	elem->prev_refaults = 0;
	elem->remaining = 0;
	elem->refault_threshold = ctx->refault_threshold;
	elem->check_ns = ctx->interval_ns;
	elem->batch_bytes = ctx->batch_bytes;
	elem->max_batches = ctx->max_batches;
	elem->swappiness = ctx->swappiness;

	wq_monitor_cgroup_id = ctx->monitor_cgroup_id;
	wq_target_cgroup_id = ctx->target_cgroup_id;

	/*
	 * Seed the refault baseline instead of leaving it at 0: a cgroup that
	 * has been running for a while has a large counter already, and the
	 * first tick would otherwise read the whole history as new refaults and
	 * open a round nobody asked for. Failing to read it is not fatal, it
	 * only costs that first spurious round.
	 */
	get_cgroup_refaults(wq_monitor_cgroup_id, &elem->prev_refaults);

	return bpf_timer_start(&elem->timer, elem->check_ns, 0);
}

char _license[] SEC("license") = "GPL";
