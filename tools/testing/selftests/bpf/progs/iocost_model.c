// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2026 KylinSoft Corporation. */
/*
 * Example iocost cost model: the builtin linear HDD formula with all costs
 * doubled, for one device given by the dev member of the struct_ops.
 *
 * The constants mirror what calc_lcoefs() derives from the AUTOP_HDD defaults
 * (rbps=174019176 rseqiops=41708 rrandiops=370, w-side analog) in vtime units
 * where 1s == 2^37. On a rotational device still on ctrl=auto, a device with
 * this model attached charges twice the builtin model under the same
 * read/write workload (the builtin prices flushes as zero and adds a fixed
 * flush term to data-bearing preflushes, which this model omits; this model
 * prices flushes as one-page writes), so the doubled cost is a direct check
 * that accounting goes through the BPF path. On a non-rotational device, or
 * one with user-pinned coefficients, the ratio to the builtin model is
 * arbitrary.
 *
 * The cursor handling follows the builtin: a zero cursor means "no previous
 * IO", and the cursor is advanced for the bios the builtin prices
 * (READ/WRITE/ZONE_APPEND with a non-zero size), so flushes and discards leave
 * it alone and long merged streams do not drift past the 16MB seek threshold.
 * One known deviation, mispricing only: the builtin does not move its cursor
 * for an IO whose cgroup fails to activate; this model does not see the
 * activation result.
 *
 * The model implements the full linear formula itself, including flushes:
 * there is no fallback to the builtin model, which prices a dataless
 * WRITE|REQ_PREFLUSH as zero unless flushiops is configured; this model prices
 * it as a one-page sequential write. What a flush actually costs depends on
 * the IOs before it, which a static formula cannot express - pricing it as a
 * small constant is a crude penalty for unnecessarily frequent flushes, and a
 * stateful model would be the way to do better. Discards and other unpriced
 * operations pass through at zero cost, like the builtin.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/*
 * VTIME_PER_SEC, IOC_PAGE_SIZE/SHIFT, IOC_SECT_TO_PAGE_SHIFT,
 * LCOEF_RANDIO_PAGES (the 16MB seek threshold) and IOCOST_COST_F_MERGE
 * come from vmlinux.h (BTF constants; the enum64 ones need pahole
 * >= 1.23 to be emitted)
 */
#define IOCOST_REQ_OP_MASK	0xff		/* REQ_OP_MASK, not in BTF */

/*
 * DIV64_U64_ROUND_UP / DIV_ROUND_UP_ULL equivalents, folded at
 * compile time
 */
#define RU(x, y)		((x) / (y) + (((x) % (y)) ? 1 : 0))

#define RBPS	174019176ULL
#define RSEQIOPS	41708ULL
#define RRANDIOPS	370ULL
#define WBPS	178075866ULL
#define WSEQIOPS	42705ULL
#define WRANDIOPS	378ULL

#define RPAGE	(RU(VTIME_PER_SEC, RU(RBPS, IOC_PAGE_SIZE)))
#define RSEQIO	(RU(VTIME_PER_SEC, RSEQIOPS) - RPAGE)
#define RRANDIO	(RU(VTIME_PER_SEC, RRANDIOPS) - RPAGE)
#define WPAGE	(RU(VTIME_PER_SEC, RU(WBPS, IOC_PAGE_SIZE)))
#define WSEQIO	(RU(VTIME_PER_SEC, WSEQIOPS) - WPAGE)
#define WRANDIO	(RU(VTIME_PER_SEC, WRANDIOPS) - WPAGE)

/*
 * per-cgroup cursor storage: keyed by the cgroup and freed with it,
 * so a cgroup that comes back starts with no cursor
 */
struct {
	__uint(type, BPF_MAP_TYPE_CGRP_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, __u64);
} cursor_store SEC(".maps");

/*
 * cgroup callback counters: the test reads them back to verify the
 * init/free pairing across attach, detach and device removal
 */
__u64 iocg_inits;
__u64 iocg_frees;

/*
 * incremented by calc_cost(): the test asserts pricing went
 * through the model while it is attached and the controller is
 * enabled
 */
__u64 calc_costs;

/* counts iocost_ioc_tick emissions observed from BPF side */
__u64 ioc_ticks;

SEC("struct_ops")
void BPF_PROG(iocost_2x_iocg_init, struct blkcg *blkcg,
	      struct request_queue *q)
{
	iocg_inits++;
}

SEC("struct_ops")
void BPF_PROG(iocost_2x_iocg_free, struct blkcg *blkcg,
	      struct request_queue *q)
{
	iocg_frees++;
}

SEC("struct_ops")
u64 BPF_PROG(iocost_2x_calc_cost, struct bio *bio, u64 model_flags)
{
	u64 opf = bio->bi_opf, nbytes = bio->bi_iter.bi_size;
	u64 sector = bio->bi_iter.bi_sector;
	struct blkcg *blkcg = bio->bi_blkg->blkcg;
	u64 pages, seek_pages = 0, base, coef_page, randio, cost;
	__u64 *cursor, cur;
	int priced;

	calc_costs++;

	/* builtin truncates: max(sectors >> IOC_SECT_TO_PAGE_SHIFT, 1) */
	pages = nbytes >> IOC_PAGE_SHIFT;
	if (!pages)
		pages = 1;

	if ((opf & IOCOST_REQ_OP_MASK) == REQ_OP_READ) {
		base = RSEQIO; coef_page = RPAGE; randio = RRANDIO;
	} else if ((opf & IOCOST_REQ_OP_MASK) == REQ_OP_WRITE ||
		   (opf & IOCOST_REQ_OP_MASK) == REQ_OP_ZONE_APPEND) {
		base = WSEQIO; coef_page = WPAGE; randio = WRANDIO;
	} else {
		/*
		 * the builtin prices other operations at zero and
		 * leaves them unthrottled; pass them through the same
		 * way instead of inventing costs
		 */
		return 0;
	}

	/* mirror the builtin cursor semantics described above */
	priced = (opf & IOCOST_REQ_OP_MASK) == REQ_OP_READ ||
		 (opf & IOCOST_REQ_OP_MASK) == REQ_OP_WRITE ||
		 (opf & IOCOST_REQ_OP_MASK) == REQ_OP_ZONE_APPEND;
	cursor = bpf_cgrp_storage_get(&cursor_store,
				      blkcg->css.cgroup, NULL,
				      BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!cursor) {
		if (model_flags & IOCOST_COST_F_MERGE)
			base = 0;
		return 2 * (base + pages * coef_page);
	}
	cur = *cursor;
	/*
	 * a size-zero IO never moves the cursor, so it must not be
	 * judged against it either; the builtin skips it entirely,
	 * this model prices it as a one-page sequential write
	 */
	if (cur && priced && nbytes) {
		seek_pages = sector > cur ? sector - cur
					   : cur - sector;
		seek_pages >>= IOC_SECT_TO_PAGE_SHIFT;
		if (seek_pages > LCOEF_RANDIO_PAGES)
			base = randio;
	}
	/*
	 * the builtin moves the cursor unconditionally on submit, but
	 * on a merge only for a back merge into the request ending at
	 * it; a merged bio starts right at the cursor exactly then,
	 * and a zero cursor means no history so it never matches
	 */
	if (priced && nbytes &&
	    (!(model_flags & IOCOST_COST_F_MERGE) || (cur && cur == sector)))
		*cursor = sector + (nbytes >> 9);

	if (model_flags & IOCOST_COST_F_MERGE)
		base = 0;

	cost = 2 * (base + pages * coef_page);
	return cost;
}

/* consumes the new iocost_ioc_tick tracepoint from BPF side */
SEC("tp_btf/iocost_ioc_tick")
__u64 BPF_PROG(iocost_2x_tick_count, struct ioc *ioc,
	       const struct ioc_now *now, int nr_active, u64 usage_us_sum)
{
	ioc_ticks++;
	return 0;
}

SEC(".struct_ops.link") /* detach on close */
struct iocost_model_ops iocost_2x = {
	.read_vtime_per_page = 2 * RPAGE,
	.write_vtime_per_page = 2 * WPAGE,
	.calc_cost = (void *)iocost_2x_calc_cost,
	.iocg_init = (void *)iocost_2x_iocg_init,
	.iocg_free = (void *)iocost_2x_iocg_free,
};

char LICENSE[] SEC("license") = "GPL";
