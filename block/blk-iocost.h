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

struct bpf_link;

/*
 * Pluggable cost model interface for blk-iocost.
 *
 * A BPF struct_ops implementation can take over the cost model of one device.
 * The device is identified by the dev member, which is set from userspace
 * before the program is loaded; the struct_ops core owns the program lifetime.
 * Attaching creates the ioc if needed, like an io.cost.model write, and
 * switches the device to the BPF model with the queue frozen before
 * rq_qos_mutex, like an io.cost.qos write, and delivers iocg_init() to the
 * cgroups which already exist on the device. Enabling and disabling the
 * controller stays with io.cost.qos.
 *
 * While a model is attached, io.cost.model selects between it and the builtin
 * model: "model=bpf" switches to the attached model and "model=linear" back to
 * the builtin. Neither detaches the struct_ops; only detaching does. The
 * builtin linear coefficients are kept while the BPF model is in use and take
 * effect again when switched back.
 *
 * While in use, the BPF model prices every charged IO on the device, including
 * flushes, from the bio charging path. calc_cost() is called from the IO
 * submission path with RCU read lock held and must not sleep. It receives the
 * bio itself so that the model can use what it needs (operation flags, size,
 * sector, the issuing cgroup through bio->bi_blkg, which is guaranteed
 * non-NULL) and returns the cost of the IO in vtime units, where 1 second
 * of device time equals VTIME_PER_SEC (2^37,
 * available to BPF programs through vmlinux.h). The return value is clamped to
 * 1 second of device time per IO.
 *
 * The struct_ops also carries the transfer cost coefficients, vtime per page
 * for reads and writes. While the BPF model is in use, they replace the
 * builtin coefficients in the completion-time request sizing of READ and
 * WRITE requests, with ZONE_APPEND counted as a write. Taking over the QoS
 * side (latency tracking, vrate control) is left for later extensions.
 *
 * The cgroup callbacks are bound to the iocg policy lifetime, one (cgroup,
 * device) pair per invocation. iocg_init() is delivered from ioc_pd_online()
 * and on attach to the cgroups already online on the device; iocg_free() on
 * detach to the cgroups which still exist then and at pd_free() time for the
 * rest, so that init and free pair up exactly. iocg_free() is gated on a
 * per-iocg delivered flag, as bios can still be priced between the blkg going
 * offline and its free. Both callbacks are called with ioc->lock held and must
 * not sleep; the delivery points nest inside queue_lock except for iocg_free()
 * from ioc_pd_free() in blkg_free_workfn().
 */

/*
 * Call metadata for calc_cost()'s model_flags; the merge indicator is not a
 * property of the bio. An enum so that the value is exported through BTF and
 * usable from vmlinux.h.
 */
enum {
	IOCOST_COST_F_MERGE	= 1 << 0,	/* called from merge path */
};

struct iocost_model_ops {
	/*
	 * target device (major:minor), set from userspace before load
	 * through the struct_ops map's initial value, in the userspace
	 * dev_t encoding new_decode_dev() accepts
	 */
	dev_t dev;

	/* vtime per page for the completion-time request sizing */
	u64 read_vtime_per_page;
	u64 write_vtime_per_page;

	u64 (*calc_cost)(struct bio *bio, u64 model_flags);
	void (*iocg_init)(struct blkcg *blkcg, struct request_queue *q);
	void (*iocg_free)(struct blkcg *blkcg, struct request_queue *q);
};

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
#ifdef CONFIG_BLK_CGROUP_IOCOST_BPF
	/* the struct_ops attached to this device, NULL = none */
	const struct iocost_model_ops	__rcu *attached;
	/* the link which owns the attachment, written with ioc->lock held */
	struct bpf_link			*bpf_link;
	/* the cost model in use, NULL = builtin linear model */
	const struct iocost_model_ops	__rcu *model;
#endif
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
#ifdef CONFIG_BLK_CGROUP_IOCOST_BPF
	/* whether the attached model's iocg_init() was delivered */
	bool				bpf_iocg_inited;
#endif

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

/*
 * The attached struct_ops and the model in use. The writers hold
 * ioc->lock, the hot path readers are inside rcu_read_lock() and the
 * map is not freed until after an RCU grace period, the slow readers
 * hold ioc->lock.
 */
static inline const struct iocost_model_ops *
ioc_attached_model_locked(struct ioc *ioc)
{
#ifdef CONFIG_BLK_CGROUP_IOCOST_BPF
	return rcu_dereference_protected(ioc->attached,
					 lockdep_is_held(&ioc->lock));
#else
	return NULL;
#endif
}

static inline const struct iocost_model_ops *
ioc_bpf_model_locked(struct ioc *ioc)
{
#ifdef CONFIG_BLK_CGROUP_IOCOST_BPF
	return rcu_dereference_protected(ioc->model,
					 lockdep_is_held(&ioc->lock));
#else
	return NULL;
#endif
}

/*
 * Price one charged IO with the model in use into *@cost and return
 * true, or return false when no model is in use and the builtin model
 * must price it. The model is read under rcu_read_lock(), which the
 * helper takes and releases itself, and the returned cost is clamped
 * to one second of device time. calc_cost() may be invoked for a
 * (cgroup, device) pair before iocg_init() has been delivered for
 * it; models relying on per-pair state must tolerate that window.
 */
#ifdef CONFIG_BLK_CGROUP_IOCOST_BPF
static inline bool ioc_model_calc_cost(struct ioc *ioc, struct bio *bio,
				       bool is_merge, u64 *cost)
{
	const struct iocost_model_ops *model;

	rcu_read_lock();
	model = rcu_dereference(ioc->model);
	if (model)
		*cost = min(model->calc_cost(bio, is_merge ?
			    IOCOST_COST_F_MERGE : 0), VTIME_PER_SEC);
	rcu_read_unlock();
	return model;
}
#else	/* CONFIG_BLK_CGROUP_IOCOST_BPF */
static inline bool ioc_model_calc_cost(struct ioc *ioc, struct bio *bio,
				       bool is_merge, u64 *cost)
{
	return false;
}
#endif	/* CONFIG_BLK_CGROUP_IOCOST_BPF */

/*
 * The same for the completion-time request sizing: the transfer cost
 * is the model's vtime per page for the request direction, and the
 * returned cost is clamped to one second of device time.
 */
#ifdef CONFIG_BLK_CGROUP_IOCOST_BPF
static inline bool ioc_model_size_cost(struct ioc *ioc, struct request *rq,
				       bool is_read, u64 *cost)
{
	const struct iocost_model_ops *model;

	rcu_read_lock();
	model = rcu_dereference(ioc->model);
	if (model)
		*cost = min((is_read ? model->read_vtime_per_page :
			     model->write_vtime_per_page) *
			    (blk_rq_stats_sectors(rq) >> IOC_SECT_TO_PAGE_SHIFT),
			    VTIME_PER_SEC);
	rcu_read_unlock();
	return model;
}
#else	/* CONFIG_BLK_CGROUP_IOCOST_BPF */
static inline bool ioc_model_size_cost(struct ioc *ioc, struct request *rq,
				       bool is_read, u64 *cost)
{
	return false;
}
#endif	/* CONFIG_BLK_CGROUP_IOCOST_BPF */

int blk_iocost_init(struct gendisk *disk);

#ifdef CONFIG_BLK_CGROUP_IOCOST_BPF
void ioc_bpf_eject(struct ioc *ioc);
#else	/* CONFIG_BLK_CGROUP_IOCOST_BPF */
static inline void ioc_bpf_eject(struct ioc *ioc) { }
#endif	/* CONFIG_BLK_CGROUP_IOCOST_BPF */
#endif	/* _BLK_IOCOST_H */
