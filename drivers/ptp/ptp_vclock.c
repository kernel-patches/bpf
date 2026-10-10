// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PTP virtual clock driver
 *
 * Copyright 2021 NXP
 */
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/math64.h>
#include "ptp_private.h"

#define PTP_VCLOCK_CC_SHIFT		31
#define PTP_VCLOCK_CC_MULT		(1 << PTP_VCLOCK_CC_SHIFT)
#define PTP_VCLOCK_FRAC_MASK		((1ULL << PTP_VCLOCK_CC_SHIFT) - 1)
#define PTP_VCLOCK_FADJ_SHIFT		9
#define PTP_VCLOCK_FADJ_DENOMINATOR	15625ULL
#define PTP_VCLOCK_REFRESH_INTERVAL	(HZ * 2)

/* protects vclock_hash addition/deletion */
static DEFINE_SPINLOCK(vclock_hash_lock);

static DEFINE_READ_MOSTLY_HASHTABLE(vclock_hash, 8);

DEFINE_STATIC_SRCU(vclock_srcu);

static void ptp_vclock_hash_add(struct ptp_vclock *vclock)
{
	spin_lock(&vclock_hash_lock);

	hlist_add_head_rcu(&vclock->vclock_hash_node,
			   &vclock_hash[vclock->clock->index % HASH_SIZE(vclock_hash)]);

	spin_unlock(&vclock_hash_lock);
}

static void ptp_vclock_hash_del(struct ptp_vclock *vclock)
{
	spin_lock(&vclock_hash_lock);

	hlist_del_init_rcu(&vclock->vclock_hash_node);

	spin_unlock(&vclock_hash_lock);

	synchronize_srcu(&vclock_srcu);
}

/*
 * Physical clock samples already contain full-width nanoseconds. Do not
 * truncate them to a 32-bit counter: failed reads can postpone a refresh
 * beyond its wrap period. Use a wide multiply and retain fractional ns.
 * Packet timestamps may precede the last sample; conversion must not move
 * the clock's anchor in that case. The caller holds vclock->lock.
 */
static u64 ptp_vclock_convert(struct ptp_vclock *vclock, u64 cycles, u64 *frac)
{
	u64 delta = cycles - vclock->cycles;
	bool backwards = delta > S64_MAX;
	u64 nsec, rem;

	if (backwards)
		delta = -delta;
	nsec = mul_u64_u32_shr(delta, vclock->mult, PTP_VCLOCK_CC_SHIFT);
	rem = (delta * vclock->mult) & PTP_VCLOCK_FRAC_MASK;
	if (backwards) {
		nsec = vclock->nsec - nsec - (rem > *frac);
		*frac = (*frac - rem) & PTP_VCLOCK_FRAC_MASK;
	} else {
		rem += *frac;
		nsec += vclock->nsec + (rem >> PTP_VCLOCK_CC_SHIFT);
		*frac = rem & PTP_VCLOCK_FRAC_MASK;
	}

	return nsec;
}

static void ptp_vclock_update(struct ptp_vclock *vclock, u64 cycles)
{
	vclock->nsec = ptp_vclock_convert(vclock, cycles, &vclock->frac);
	vclock->cycles = cycles;
}

/* The caller holds vclock->lock, or has not published the clock yet. */
static int ptp_vclock_sample(struct ptp_vclock *vclock, u64 *cycles)
{
	struct ptp_clock *ptp = vclock->pclock;
	struct timespec64 ts;
	int err;

	err = ptp->info->getcycles64(ptp->info, &ts);
	if (!err)
		*cycles = timespec64_to_ns(&ts);
	return err;
}

static int ptp_vclock_adjfine(struct ptp_clock_info *ptp, long scaled_ppm)
{
	struct ptp_vclock *vclock = info_to_vclock(ptp);
	u64 cycles;
	s64 adj;
	int err;

	adj = (s64)scaled_ppm << PTP_VCLOCK_FADJ_SHIFT;
	adj = div_s64(adj, PTP_VCLOCK_FADJ_DENOMINATOR);

	if (mutex_lock_interruptible(&vclock->lock))
		return -EINTR;
	err = ptp_vclock_sample(vclock, &cycles);
	if (!err) {
		ptp_vclock_update(vclock, cycles);
		vclock->mult = PTP_VCLOCK_CC_MULT + adj;
	}
	mutex_unlock(&vclock->lock);

	return err;
}

static int ptp_vclock_adjtime(struct ptp_clock_info *ptp, s64 delta)
{
	struct ptp_vclock *vclock = info_to_vclock(ptp);

	if (mutex_lock_interruptible(&vclock->lock))
		return -EINTR;
	vclock->nsec += delta;
	mutex_unlock(&vclock->lock);

	return 0;
}

static int ptp_vclock_gettime(struct ptp_clock_info *ptp,
			      struct timespec64 *ts)
{
	struct ptp_vclock *vclock = info_to_vclock(ptp);
	u64 cycles;
	int err;

	if (mutex_lock_interruptible(&vclock->lock))
		return -EINTR;
	err = ptp_vclock_sample(vclock, &cycles);
	if (!err) {
		ptp_vclock_update(vclock, cycles);
		*ts = ns_to_timespec64(vclock->nsec);
	}
	mutex_unlock(&vclock->lock);

	return err;
}

static int ptp_vclock_gettimex(struct ptp_clock_info *ptp,
			       struct timespec64 *ts,
			       struct ptp_system_timestamp *sts)
{
	struct ptp_vclock *vclock = info_to_vclock(ptp);
	struct ptp_clock *pptp = vclock->pclock;
	struct timespec64 pts;
	int err;

	if (mutex_lock_interruptible(&vclock->lock))
		return -EINTR;
	err = pptp->info->getcyclesx64(pptp->info, &pts, sts);
	if (!err) {
		ptp_vclock_update(vclock, timespec64_to_ns(&pts));
		*ts = ns_to_timespec64(vclock->nsec);
	}
	mutex_unlock(&vclock->lock);

	return err;
}

static int ptp_vclock_settime(struct ptp_clock_info *ptp,
			      const struct timespec64 *ts)
{
	struct ptp_vclock *vclock = info_to_vclock(ptp);
	u64 cycles;
	int err;

	if (mutex_lock_interruptible(&vclock->lock))
		return -EINTR;
	err = ptp_vclock_sample(vclock, &cycles);
	if (!err) {
		vclock->cycles = cycles;
		vclock->nsec = timespec64_to_ns(ts);
		vclock->frac = 0;
	}
	mutex_unlock(&vclock->lock);

	return err;
}

static int ptp_vclock_getcrosststamp(struct ptp_clock_info *ptp,
				     struct system_device_crosststamp *xtstamp)
{
	struct ptp_vclock *vclock = info_to_vclock(ptp);
	struct ptp_clock *pptp = vclock->pclock;
	int err;

	if (mutex_lock_interruptible(&vclock->lock))
		return -EINTR;
	err = pptp->info->getcrosscycles(pptp->info, xtstamp);
	if (!err) {
		ptp_vclock_update(vclock, ktime_to_ns(xtstamp->device));
		xtstamp->device = ns_to_ktime(vclock->nsec);
	}
	mutex_unlock(&vclock->lock);

	return err;
}

static long ptp_vclock_refresh(struct ptp_clock_info *ptp)
{
	struct ptp_vclock *vclock = info_to_vclock(ptp);
	struct timespec64 ts;

	ptp_vclock_gettime(&vclock->info, &ts);

	return PTP_VCLOCK_REFRESH_INTERVAL;
}

static void ptp_vclock_set_subclass(struct ptp_clock *ptp)
{
	lockdep_set_subclass(&ptp->clock.rwsem, PTP_LOCK_VIRTUAL);
}

static const struct ptp_clock_info ptp_vclock_info = {
	.owner		= THIS_MODULE,
	.name		= "ptp virtual clock",
	.max_adj	= 500000000,
	.adjfine	= ptp_vclock_adjfine,
	.adjtime	= ptp_vclock_adjtime,
	.settime64	= ptp_vclock_settime,
	.do_aux_work	= ptp_vclock_refresh,
};

struct ptp_vclock *ptp_vclock_register(struct ptp_clock *pclock)
{
	struct ptp_vclock *vclock;

	vclock = kzalloc_obj(*vclock);
	if (!vclock)
		return NULL;

	vclock->pclock = pclock;
	vclock->info = ptp_vclock_info;
	if (pclock->info->getcyclesx64)
		vclock->info.gettimex64 = ptp_vclock_gettimex;
	else
		vclock->info.gettime64 = ptp_vclock_gettime;
	if (pclock->info->getcrosscycles)
		vclock->info.getcrosststamp = ptp_vclock_getcrosststamp;
	vclock->mult = PTP_VCLOCK_CC_MULT;

	snprintf(vclock->info.name, PTP_CLOCK_NAME_LEN, "ptp%d_virt",
		 pclock->index);

	INIT_HLIST_NODE(&vclock->vclock_hash_node);

	mutex_init(&vclock->lock);

	if (ptp_vclock_sample(vclock, &vclock->cycles)) {
		kfree(vclock);
		return NULL;
	}

	vclock->clock = ptp_clock_register(&vclock->info, &pclock->dev);
	if (IS_ERR_OR_NULL(vclock->clock)) {
		kfree(vclock);
		return NULL;
	}

	ptp_vclock_set_subclass(vclock->clock);

	ptp_schedule_worker(vclock->clock, PTP_VCLOCK_REFRESH_INTERVAL);

	ptp_vclock_hash_add(vclock);

	return vclock;
}

void ptp_vclock_unregister(struct ptp_vclock *vclock)
{
	ptp_vclock_hash_del(vclock);

	ptp_clock_unregister(vclock->clock);
	kfree(vclock);
}

#if IS_BUILTIN(CONFIG_PTP_1588_CLOCK)
int ptp_get_vclocks_index(int pclock_index, int **vclock_index)
{
	char name[PTP_CLOCK_NAME_LEN] = "";
	struct ptp_clock *ptp;
	struct device *dev;
	int num = 0;

	if (pclock_index < 0)
		return num;

	snprintf(name, PTP_CLOCK_NAME_LEN, "ptp%d", pclock_index);
	dev = class_find_device_by_name(&ptp_class, name);
	if (!dev)
		return num;

	ptp = dev_get_drvdata(dev);

	if (mutex_lock_interruptible(&ptp->n_vclocks_mux)) {
		put_device(dev);
		return num;
	}

	*vclock_index = kzalloc(sizeof(int) * ptp->n_vclocks, GFP_KERNEL);
	if (!(*vclock_index))
		goto out;

	memcpy(*vclock_index, ptp->vclock_index, sizeof(int) * ptp->n_vclocks);
	num = ptp->n_vclocks;
out:
	mutex_unlock(&ptp->n_vclocks_mux);
	put_device(dev);
	return num;
}
EXPORT_SYMBOL(ptp_get_vclocks_index);

ktime_t ptp_convert_timestamp(const ktime_t *hwtstamp, int vclock_index)
{
	unsigned int hash = vclock_index % HASH_SIZE(vclock_hash);
	struct ptp_vclock *vclock;
	u64 vclock_ns = 0;
	int srcu_idx;
	u64 ns, frac;

	ns = ktime_to_ns(*hwtstamp);

	srcu_idx = srcu_read_lock(&vclock_srcu);

	hlist_for_each_entry_srcu(vclock, &vclock_hash[hash], vclock_hash_node,
				  srcu_read_lock_held(&vclock_srcu)) {
		if (vclock->clock->index != vclock_index)
			continue;

		if (mutex_lock_interruptible(&vclock->lock))
			break;
		frac = vclock->frac;
		vclock_ns = ptp_vclock_convert(vclock, ns, &frac);
		mutex_unlock(&vclock->lock);
		break;
	}

	srcu_read_unlock(&vclock_srcu, srcu_idx);

	return ns_to_ktime(vclock_ns);
}
EXPORT_SYMBOL(ptp_convert_timestamp);
#endif
