/* SPDX-License-Identifier: GPL-2.0 */
/*
 * blk-iocost private definitions, shared between blk-iocost.c and
 * blk-iocost-bpf.c. Not for direct inclusion by other files.
 */
#ifndef _BLK_IOCOST_H
#define _BLK_IOCOST_H

#include <linux/types.h>
#include <linux/blk_types.h>
#include <linux/blkdev.h>
#include "blk-cgroup.h"
#include <linux/blk-mq.h>
#include <linux/timer.h>
#include <linux/hrtimer.h>
#include <linux/seqlock.h>
#include <linux/atomic.h>
#include <linux/minmax.h>
#include <linux/time64.h>
#include <linux/wait.h>
#include <asm/local.h>
#include <asm/local64.h>
#include "blk-rq-qos.h"

enum {
	MILLION			= 1000000,

	/* timer period is calculated from latency requirements, bound it */
	MIN_PERIOD		= USEC_PER_MSEC,
	MAX_PERIOD		= USEC_PER_SEC,

	/*
	 * iocg->vtime is targeted at 50% behind the device vtime, which
	 * serves as its IO credit buffer.  Surplus weight adjustment is
	 * immediately canceled if the vtime margin runs below 10%.
	 */
	MARGIN_MIN_PCT		= 10,
	MARGIN_LOW_PCT		= 20,
	MARGIN_TARGET_PCT	= 50,

	INUSE_ADJ_STEP_PCT	= 25,

	/* Have some play in timer operations */
	TIMER_SLACK_PCT		= 1,

	/* 1/64k is granular enough and can easily be handled w/ u32 */
	WEIGHT_ONE		= 1 << 16,
};

enum {
	/*
	 * As vtime is used to calculate the cost of each IO, it needs to
	 * be fairly high precision.  For example, it should be able to
	 * represent the cost of a single page worth of discard with
	 * suffificient accuracy.  At the same time, it should be able to
	 * represent reasonably long enough durations to be useful and
	 * convenient during operation.
	 *
	 * 1s worth of vtime is 2^37.  This gives us both sub-nanosecond
	 * granularity and days of wrap-around time even at extreme vrates.
	 */
	VTIME_PER_SEC_SHIFT	= 37,
	VTIME_PER_SEC		= 1LLU << VTIME_PER_SEC_SHIFT,
	VTIME_PER_USEC		= VTIME_PER_SEC / USEC_PER_SEC,
	VTIME_PER_NSEC		= VTIME_PER_SEC / NSEC_PER_SEC,

	/* bound vrate adjustments within two orders of magnitude */
	VRATE_MIN_PPM		= 10000,	/* 1% */
	VRATE_MAX_PPM		= 100000000,	/* 10000% */

	VRATE_MIN		= VTIME_PER_USEC * VRATE_MIN_PPM / MILLION,
	VRATE_CLAMP_ADJ_PCT	= 4,

	/* switch iff the conditions are met for longer than this */
	AUTOP_CYCLE_NSEC	= 10LLU * NSEC_PER_SEC,
};

enum {
	/* if IOs end up waiting for requests, issue less */
	RQ_WAIT_BUSY_PCT	= 5,

	/* unbusy hysterisis */
	UNBUSY_THR_PCT		= 75,

	/*
	 * The effect of delay is indirect and non-linear and a huge amount of
	 * future debt can accumulate abruptly while unthrottled. Linearly scale
	 * up delay as debt is going up and then let it decay exponentially.
	 * This gives us quick ramp ups while delay is accumulating and long
	 * tails which can help reducing the frequency of debt explosions on
	 * unthrottle. The parameters are experimentally determined.
	 *
	 * The delay mechanism provides adequate protection and behavior in many
	 * cases. However, this is far from ideal and falls shorts on both
	 * fronts. The debtors are often throttled too harshly costing a
	 * significant level of fairness and possibly total work while the
	 * protection against their impacts on the system can be choppy and
	 * unreliable.
	 *
	 * The shortcoming primarily stems from the fact that, unlike for page
	 * cache, the kernel doesn't have well-defined back-pressure propagation
	 * mechanism and policies for anonymous memory. Fully addressing this
	 * issue will likely require substantial improvements in the area.
	 */
	MIN_DELAY_THR_PCT	= 500,
	MAX_DELAY_THR_PCT	= 25000,
	MIN_DELAY		= 250,
	MAX_DELAY		= 250 * USEC_PER_MSEC,

	/* halve debts if avg usage over 100ms is under 50% */
	DFGV_USAGE_PCT		= 50,
	DFGV_PERIOD		= 100 * USEC_PER_MSEC,

	/* don't let cmds which take a very long time pin lagging for too long */
	MAX_LAGGING_PERIODS	= 10,

	/*
	 * Count IO size in 4k pages.  The 12bit shift helps keeping
	 * size-proportional components of cost calculation in closer
	 * numbers of digits to per-IO cost components.
	 */
	IOC_PAGE_SHIFT		= 12,
	IOC_PAGE_SIZE		= 1 << IOC_PAGE_SHIFT,
	IOC_SECT_TO_PAGE_SHIFT	= IOC_PAGE_SHIFT - SECTOR_SHIFT,

	/* if apart further than 16M, consider randio for linear model */
	LCOEF_RANDIO_PAGES	= 4096,
};

enum ioc_running {
	IOC_IDLE,
	IOC_RUNNING,
	IOC_STOP,
};

/* io.cost.qos controls including per-dev enable of the whole controller */
enum {
	QOS_ENABLE,
	QOS_CTRL,
	NR_QOS_CTRL_PARAMS,
};

/* io.cost.qos params */
enum {
	QOS_RPPM,
	QOS_RLAT,
	QOS_WPPM,
	QOS_WLAT,
	QOS_MIN,
	QOS_MAX,
	NR_QOS_PARAMS,
};

/* io.cost.model controls */
enum {
	COST_CTRL,
	COST_MODEL,
	NR_COST_CTRL_PARAMS,
};

/* builtin linear cost model coefficients */
enum {
	I_LCOEF_RBPS,
	I_LCOEF_RSEQIOPS,
	I_LCOEF_RRANDIOPS,
	I_LCOEF_WBPS,
	I_LCOEF_WSEQIOPS,
	I_LCOEF_WRANDIOPS,
	I_LCOEF_FLUSHIOPS,
	NR_I_LCOEFS,
};

enum {
	LCOEF_RPAGE,
	LCOEF_RSEQIO,
	LCOEF_RRANDIO,
	LCOEF_WPAGE,
	LCOEF_WSEQIO,
	LCOEF_WRANDIO,
	LCOEF_FLUSH,
	NR_LCOEFS,
};

enum {
	AUTOP_INVALID,
	AUTOP_HDD,
	AUTOP_SSD_QD1,
	AUTOP_SSD_DFL,
	AUTOP_SSD_FAST,
};

struct ioc_params {
	u32				qos[NR_QOS_PARAMS];
	u64				i_lcoefs[NR_I_LCOEFS];
	u64				lcoefs[NR_LCOEFS];
	u32				too_fast_vrate_pct;
	u32				too_slow_vrate_pct;
};

struct ioc_margins {
	s64				min;
	s64				low;
	s64				target;
};

struct ioc_missed {
	local_t				nr_met;
	local_t				nr_missed;
	u32				last_met;
	u32				last_missed;
};

struct ioc_pcpu_stat {
	struct ioc_missed		missed[2];

	local64_t			rq_wait_ns;
	u64				last_rq_wait_ns;
};

/* per device */
struct ioc {
	struct rq_qos			rqos;

	bool				enabled;

	struct ioc_params		params;
	struct ioc_margins		margins;
	u32				period_us;
	u32				timer_slack_ns;
	u64				vrate_min;
	u64				vrate_max;

	spinlock_t			lock;
	struct timer_list		timer;
	struct list_head		active_iocgs;	/* active cgroups */
	struct ioc_pcpu_stat __percpu	*pcpu_stat;

	enum ioc_running		running;
	atomic64_t			vtime_rate;
	u64				vtime_base_rate;
	s64				vtime_err;

	seqcount_spinlock_t		period_seqcount;
	u64				period_at;	/* wallclock starttime */
	u64				period_at_vtime; /* vtime starttime */

	atomic64_t			cur_period;	/* inc'd each period */
	int				busy_level;	/* saturation history */

	bool				weights_updated;
	atomic_t			hweight_gen;	/* for lazy hweights */

	/* debt forgivness */
	u64				dfgv_period_at;
	u64				dfgv_period_rem;
	u64				dfgv_usage_us_sum;

	u64				autop_too_fast_at;
	u64				autop_too_slow_at;
	int				autop_idx;
	bool				user_qos_params:1;
	bool				user_cost_model:1;

};

struct iocg_pcpu_stat {
	local64_t			abs_vusage;
};

struct iocg_stat {
	u64				usage_us;
	u64				wait_us;
	u64				indebt_us;
	u64				indelay_us;
};

/* per device-cgroup pair */
struct ioc_gq {
	struct blkg_policy_data		pd;
	struct ioc			*ioc;

	/*
	 * A iocg can get its weight from two sources - an explicit
	 * per-device-cgroup configuration or the default weight of the
	 * cgroup.  `cfg_weight` is the explicit per-device-cgroup
	 * configuration.  `weight` is the effective considering both
	 * sources.
	 *
	 * When an idle cgroup becomes active its `active` goes from 0 to
	 * `weight`.  `inuse` is the surplus adjusted active weight.
	 * `active` and `inuse` are used to calculate `hweight_active` and
	 * `hweight_inuse`.
	 *
	 * `last_inuse` remembers `inuse` while an iocg is idle to persist
	 * surplus adjustments.
	 *
	 * `inuse` may be adjusted dynamically during period. `saved_*` are used
	 * to determine and track adjustments.
	 */
	u32				cfg_weight;
	u32				weight;
	u32				active;
	u32				inuse;

	u32				last_inuse;
	s64				saved_margin;

	sector_t			cursor;		/* to detect randio */

	/*
	 * `vtime` is this iocg's vtime cursor which progresses as IOs are
	 * issued.  If lagging behind device vtime, the delta represents
	 * the currently available IO budget.  If running ahead, the
	 * overage.
	 *
	 * `vtime_done` is the same but progressed on completion rather
	 * than issue.  The delta behind `vtime` represents the cost of
	 * currently in-flight IOs.
	 */
	atomic64_t			vtime;
	atomic64_t			done_vtime;
	u64				abs_vdebt;

	/* current delay in effect and when it started */
	u64				delay;
	u64				delay_at;

	/*
	 * The period this iocg was last active in.  Used for deactivation
	 * and invalidating `vtime`.
	 */
	atomic64_t			active_period;
	struct list_head		active_list;

	/* see __propagate_weights() and current_hweight() for details */
	u64				child_active_sum;
	u64				child_inuse_sum;
	u64				child_adjusted_sum;
	int				hweight_gen;
	u32				hweight_active;
	u32				hweight_inuse;
	u32				hweight_donating;
	u32				hweight_after_donation;

	struct list_head		walk_list;
	struct list_head		surplus_list;

	struct wait_queue_head		waitq;
	struct hrtimer			waitq_timer;

	/* timestamp at the latest activation */
	u64				activated_at;

	/* statistics */
	struct iocg_pcpu_stat __percpu	*pcpu_stat;
	struct iocg_stat		stat;
	struct iocg_stat		last_stat;
	u64				last_stat_abs_vusage;
	u64				usage_delta_us;
	u64				wait_since;
	u64				indebt_since;
	u64				indelay_since;

	/* this iocg's depth in the hierarchy and ancestors including self */
	int				level;
	struct ioc_gq			*ancestors[];
};

/* per cgroup */
struct ioc_cgrp {
	struct blkcg_policy_data	cpd;
	unsigned int			dfl_weight;
};

struct ioc_now {
	u64				now_ns;
	u64				now;
	u64				vnow;
};

struct iocg_wait {
	struct wait_queue_entry		wait;
	struct bio			*bio;
	u64				abs_cost;
	bool				committed;
};

struct iocg_wake_ctx {
	struct ioc_gq			*iocg;
	u32				hw_inuse;
	s64				vbudget;
};

extern struct blkcg_policy blkcg_policy_iocost;

static inline struct ioc *rqos_to_ioc(struct rq_qos *rqos)
{
	return container_of(rqos, struct ioc, rqos);
}

static inline struct ioc *q_to_ioc(struct request_queue *q)
{
	return rqos_to_ioc(rq_qos_id(q, RQ_QOS_COST));
}

static inline const char __maybe_unused *ioc_name(struct ioc *ioc)
{
	struct gendisk *disk = ioc->rqos.disk;

	if (!disk)
		return "<unknown>";
	return disk->disk_name;
}

static inline struct ioc_gq *pd_to_iocg(struct blkg_policy_data *pd)
{
	return pd ? container_of(pd, struct ioc_gq, pd) : NULL;
}

static inline struct ioc_gq *blkg_to_iocg(struct blkcg_gq *blkg)
{
	return pd_to_iocg(blkg_to_pd(blkg, &blkcg_policy_iocost));
}

static inline struct blkcg_gq *iocg_to_blkg(struct ioc_gq *iocg)
{
	return pd_to_blkg(&iocg->pd);
}

static inline struct ioc_cgrp *blkcg_to_iocc(struct blkcg *blkcg)
{
	return container_of(blkcg_to_cpd(blkcg, &blkcg_policy_iocost),
			    struct ioc_cgrp, cpd);
}

#endif	/* _BLK_IOCOST_H */
