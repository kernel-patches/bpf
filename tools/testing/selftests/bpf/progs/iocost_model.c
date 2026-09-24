// SPDX-License-Identifier: GPL-2.0
/*
 * Example iocost cost model: the builtin linear HDD formula with all
 * costs doubled, for one device given by the dev member of the
 * struct_ops.
 *
 * The constants mirror what calc_lcoefs() derives from the AUTOP_HDD
 * defaults (rbps=174019176 rseqiops=41708 rrandiops=370, w-side
 * analog) in vtime units where 1s == 2^37.  On a rotational device
 * still on ctrl=auto, a device with this model attached charges
 * twice the builtin model under the same workload, so the
 * doubled cost is a direct check that accounting goes through the
 * BPF path.  On a non-rotational device, or one with user-pinned
 * coefficients, the ratio to the builtin model is arbitrary.
 *
 * A zero cursor means "no previous IO".  The cursor advances for
 * every priced bio with a non-zero size (READ/WRITE), merged ones
 * included, truncating to whole sectors like the builtin, so flushes
 * and discards leave it alone and merged streams do not drift past
 * the 16MB seek threshold.
 *
 * The model implements the full linear formula itself, including
 * flushes: there is no fallback to the builtin model, a dataless
 * A dataless WRITE|REQ_PREFLUSH keeps the write base: the op is still
 * WRITE, so it carries WSEQIO (or WRANDIO after a seek) plus one page.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/*
 * VTIME_PER_SEC, IOC_PAGE_SIZE/SHIFT, IOC_SECT_TO_PAGE_SHIFT and
 * IOCOST_COST_F_MERGE come from vmlinux.h (BTF enum constants)
 */
#define LCOEF_RANDIO_PAGES	4096	/* 16MB seek threshold */
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
 * per-cgroup cursor storage: keyed by the cgroup, freed with it, so
 * per-cgroup state follows the cgroup lifetime
 */
struct {
	__uint(type, BPF_MAP_TYPE_CGRP_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, __u64);
} cursor_store SEC(".maps");

SEC("struct_ops")
u64 BPF_PROG(iocost_2x_calc_cost, struct bio *bio, u64 model_flags)
{
	u64 opf = bio->bi_opf, nbytes = bio->bi_iter.bi_size;
	u64 sector = bio->bi_iter.bi_sector;
	struct blkcg *blkcg = bio->bi_blkg->blkcg;
	u64 pages, seek_pages = 0, base, coef_page, randio, cost;
	__u64 *cursor, cur;
	int priced;

	/* builtin truncates: max(sectors >> IOC_SECT_TO_PAGE_SHIFT, 1) */
	pages = nbytes >> IOC_PAGE_SHIFT;
	if (!pages)
		pages = 1;

	if ((opf & IOCOST_REQ_OP_MASK) == REQ_OP_READ) {
		base = RSEQIO; coef_page = RPAGE; randio = RRANDIO;
	} else if ((opf & IOCOST_REQ_OP_MASK) == REQ_OP_WRITE) {
		base = WSEQIO; coef_page = WPAGE; randio = WRANDIO;
	} else {
		/*
		 * a fully owning model must price every op; unknown
		 * ops are priced as a single page write
		 */
		base = 0; coef_page = WPAGE; randio = 0;
	}

	/*
	 * mirror the builtin cursor semantics: seek distance is only
	 * computed against a non-zero cursor, and the cursor is
	 * advanced for bios the builtin prices (READ/WRITE with a
	 * non-zero size), merged ones included, so flushes and
	 * discards leave it alone
	 */
	priced = (opf & IOCOST_REQ_OP_MASK) == REQ_OP_READ ||
		 (opf & IOCOST_REQ_OP_MASK) == REQ_OP_WRITE;
	cursor = bpf_cgrp_storage_get(&cursor_store,
				      blkcg->css.cgroup, NULL,
				      BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!cursor) {
		if (model_flags & IOCOST_COST_F_MERGE)
			base = 0;
		return 2 * (base + pages * coef_page);
	}
	cur = *cursor;
	if (cur && priced) {
		seek_pages = sector > cur ? sector - cur
					   : cur - sector;
		seek_pages >>= IOC_SECT_TO_PAGE_SHIFT;
		if (seek_pages > LCOEF_RANDIO_PAGES)
			base = randio;
	}
	if (priced && nbytes)
		*cursor = sector + (nbytes >> 9);

	if (model_flags & IOCOST_COST_F_MERGE)
		base = 0;

	cost = 2 * (base + pages * coef_page);
	return cost;
}

SEC(".struct_ops")
struct iocost_model_ops iocost_2x = {
	.read_vtime_per_page = 2 * RPAGE,
	.write_vtime_per_page = 2 * WPAGE,
	.calc_cost = (void *)iocost_2x_calc_cost,
};

char LICENSE[] SEC("license") = "GPL";
