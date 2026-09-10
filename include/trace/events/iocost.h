/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM iocost

struct ioc;
struct ioc_now;
struct ioc_gq;

#if !defined(_TRACE_BLK_IOCOST_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_BLK_IOCOST_H

#include <linux/tracepoint.h>

DECLARE_EVENT_CLASS(iocost_iocg_state,

	TP_PROTO(struct ioc_gq *iocg, const char *path, struct ioc_now *now,
		u64 last_period, u64 cur_period, u64 vtime),

	TP_ARGS(iocg, path, now, last_period, cur_period, vtime),

	TP_STRUCT__entry (
		__string(devname, ioc_name(iocg->ioc))
		__string(cgroup, path)
		__field(u64, now)
		__field(u64, vnow)
		__field(u64, vrate)
		__field(u64, last_period)
		__field(u64, cur_period)
		__field(u64, vtime)
		__field(u32, weight)
		__field(u32, inuse)
		__field(u64, hweight_active)
		__field(u64, hweight_inuse)
	),

	TP_fast_assign(
		__assign_str(devname);
		__assign_str(cgroup);
		__entry->now = now->now;
		__entry->vnow = now->vnow;
		__entry->vrate = iocg->ioc->vtime_base_rate;
		__entry->last_period = last_period;
		__entry->cur_period = cur_period;
		__entry->vtime = vtime;
		__entry->weight = iocg->weight;
		__entry->inuse = iocg->inuse;
		__entry->hweight_active = iocg->hweight_active;
		__entry->hweight_inuse = iocg->hweight_inuse;
	),

	TP_printk("[%s:%s] now=%llu:%llu vrate=%llu "
		  "period=%llu->%llu vtime=%llu "
		  "weight=%u/%u hweight=%llu/%llu",
		__get_str(devname), __get_str(cgroup),
		__entry->now, __entry->vnow, __entry->vrate,
		__entry->last_period, __entry->cur_period,
		__entry->vtime, __entry->inuse, __entry->weight,
		__entry->hweight_inuse, __entry->hweight_active
	)
);

DEFINE_EVENT(iocost_iocg_state, iocost_iocg_activate,
	TP_PROTO(struct ioc_gq *iocg, const char *path, struct ioc_now *now,
		 u64 last_period, u64 cur_period, u64 vtime),

	TP_ARGS(iocg, path, now, last_period, cur_period, vtime)
);

DEFINE_EVENT(iocost_iocg_state, iocost_iocg_idle,
	TP_PROTO(struct ioc_gq *iocg, const char *path, struct ioc_now *now,
		 u64 last_period, u64 cur_period, u64 vtime),

	TP_ARGS(iocg, path, now, last_period, cur_period, vtime)
);

DECLARE_EVENT_CLASS(iocg_inuse_update,

	TP_PROTO(struct ioc_gq *iocg, const char *path, struct ioc_now *now,
		u32 old_inuse, u32 new_inuse,
		u64 old_hw_inuse, u64 new_hw_inuse),

	TP_ARGS(iocg, path, now, old_inuse, new_inuse,
		old_hw_inuse, new_hw_inuse),

	TP_STRUCT__entry (
		__string(devname, ioc_name(iocg->ioc))
		__string(cgroup, path)
		__field(u64, now)
		__field(u32, old_inuse)
		__field(u32, new_inuse)
		__field(u64, old_hweight_inuse)
		__field(u64, new_hweight_inuse)
	),

	TP_fast_assign(
		__assign_str(devname);
		__assign_str(cgroup);
		__entry->now = now->now;
		__entry->old_inuse = old_inuse;
		__entry->new_inuse = new_inuse;
		__entry->old_hweight_inuse = old_hw_inuse;
		__entry->new_hweight_inuse = new_hw_inuse;
	),

	TP_printk("[%s:%s] now=%llu inuse=%u->%u hw_inuse=%llu->%llu",
		__get_str(devname), __get_str(cgroup), __entry->now,
		__entry->old_inuse, __entry->new_inuse,
		__entry->old_hweight_inuse, __entry->new_hweight_inuse
	)
);

DEFINE_EVENT(iocg_inuse_update, iocost_inuse_shortage,

	TP_PROTO(struct ioc_gq *iocg, const char *path, struct ioc_now *now,
		u32 old_inuse, u32 new_inuse,
		u64 old_hw_inuse, u64 new_hw_inuse),

	TP_ARGS(iocg, path, now, old_inuse, new_inuse,
		old_hw_inuse, new_hw_inuse)
);

DEFINE_EVENT(iocg_inuse_update, iocost_inuse_transfer,

	TP_PROTO(struct ioc_gq *iocg, const char *path, struct ioc_now *now,
		u32 old_inuse, u32 new_inuse,
		u64 old_hw_inuse, u64 new_hw_inuse),

	TP_ARGS(iocg, path, now, old_inuse, new_inuse,
		old_hw_inuse, new_hw_inuse)
);

DEFINE_EVENT(iocg_inuse_update, iocost_inuse_adjust,

	TP_PROTO(struct ioc_gq *iocg, const char *path, struct ioc_now *now,
		u32 old_inuse, u32 new_inuse,
		u64 old_hw_inuse, u64 new_hw_inuse),

	TP_ARGS(iocg, path, now, old_inuse, new_inuse,
		old_hw_inuse, new_hw_inuse)
);

TRACE_EVENT(iocost_ioc_vrate_adj,

	TP_PROTO(struct ioc *ioc, u64 new_vrate, u32 *missed_ppm,
		u32 rq_wait_pct, int nr_lagging, int nr_shortages),

	TP_ARGS(ioc, new_vrate, missed_ppm, rq_wait_pct, nr_lagging, nr_shortages),

	TP_STRUCT__entry (
		__string(devname, ioc_name(ioc))
		__field(u64, old_vrate)
		__field(u64, new_vrate)
		__field(int, busy_level)
		__field(u32, read_missed_ppm)
		__field(u32, write_missed_ppm)
		__field(u32, rq_wait_pct)
		__field(int, nr_lagging)
		__field(int, nr_shortages)
	),

	TP_fast_assign(
		__assign_str(devname);
		__entry->old_vrate = ioc->vtime_base_rate;
		__entry->new_vrate = new_vrate;
		__entry->busy_level = ioc->busy_level;
		__entry->read_missed_ppm = missed_ppm[READ];
		__entry->write_missed_ppm = missed_ppm[WRITE];
		__entry->rq_wait_pct = rq_wait_pct;
		__entry->nr_lagging = nr_lagging;
		__entry->nr_shortages = nr_shortages;
	),

	TP_printk("[%s] vrate=%llu->%llu busy=%d missed_ppm=%u:%u rq_wait_pct=%u lagging=%d shortages=%d",
		__get_str(devname), __entry->old_vrate, __entry->new_vrate,
		__entry->busy_level,
		__entry->read_missed_ppm, __entry->write_missed_ppm,
		__entry->rq_wait_pct, __entry->nr_lagging, __entry->nr_shortages
	)
);

/*
 * Periodic per-device summary, emitted once per period from the tail of
 * ioc_timer_fn().  Unlike the state-change events above, this fires every
 * period the controller is running, including steady states, and carries
 * the overall controller state so basic monitoring doesn't require drgn.
 */
TRACE_EVENT(iocost_ioc_tick,

	TP_PROTO(struct ioc *ioc, int nr_active, u64 usage_us_sum),

	TP_ARGS(ioc, nr_active, usage_us_sum),

	TP_STRUCT__entry (
		__string(devname, ioc_name(ioc))
		__field(u32, period_us)
		__field(u64, vrate)
		__field(int, busy_level)
		__field(int, nr_active)
		__field(u32, usage_pct)
		__field(int, running)
	),

	TP_fast_assign(
		__assign_str(devname);
		__entry->period_us = ioc->period_us;
		__entry->vrate = ioc->vtime_base_rate;
		__entry->busy_level = ioc->busy_level;
		__entry->nr_active = nr_active;
		__entry->usage_pct = ioc->period_us ?
			div_u64(usage_us_sum * 100, ioc->period_us) : 0;
		__entry->running = ioc->running;
	),

	TP_printk("[%s] period=%uus vrate=%llu busy=%d active=%d usage=%u%% running=%d",
		__get_str(devname), __entry->period_us, __entry->vrate,
		__entry->busy_level, __entry->nr_active, __entry->usage_pct,
		__entry->running
	)
);

TRACE_EVENT(iocost_iocg_forgive_debt,

	TP_PROTO(struct ioc_gq *iocg, const char *path, struct ioc_now *now,
		u32 usage_pct, u64 old_debt, u64 new_debt,
		u64 old_delay, u64 new_delay),

	TP_ARGS(iocg, path, now, usage_pct,
		old_debt, new_debt, old_delay, new_delay),

	TP_STRUCT__entry (
		__string(devname, ioc_name(iocg->ioc))
		__string(cgroup, path)
		__field(u64, now)
		__field(u64, vnow)
		__field(u32, usage_pct)
		__field(u64, old_debt)
		__field(u64, new_debt)
		__field(u64, old_delay)
		__field(u64, new_delay)
	),

	TP_fast_assign(
		__assign_str(devname);
		__assign_str(cgroup);
		__entry->now = now->now;
		__entry->vnow = now->vnow;
		__entry->usage_pct = usage_pct;
		__entry->old_debt = old_debt;
		__entry->new_debt = new_debt;
		__entry->old_delay = old_delay;
		__entry->new_delay = new_delay;
	),

	TP_printk("[%s:%s] now=%llu:%llu usage=%u debt=%llu->%llu delay=%llu->%llu",
		__get_str(devname), __get_str(cgroup),
		__entry->now, __entry->vnow, __entry->usage_pct,
		__entry->old_debt, __entry->new_debt,
		__entry->old_delay, __entry->new_delay
	)
);

#endif /* _TRACE_BLK_IOCOST_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
