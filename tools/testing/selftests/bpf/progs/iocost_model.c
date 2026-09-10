// SPDX-License-Identifier: GPL-2.0
/*
 * Example iocost cost model: the builtin linear HDD formula with all
 * costs doubled.
 *
 * The constants mirror what calc_lcoefs() derives from the AUTOP_HDD
 * defaults (rbps=174019176 rseqiops=41708 rrandiops=370, w-side
 * analog) in vtime units where 1s == 2^37, expressed with the same
 * round-up divisions so they cannot drift from the kernel.  A device
 * bound to this model through io.cost.model charges exactly twice the
 * builtin model under the same workload, which makes it a convenient
 * way to verify that accounting goes through the BPF path.
 *
 * The model implements the full linear formula itself, including
 * flushes: there is no fallback to the builtin model, a dataless
 * WRITE|REQ_PREFLUSH is priced as a one-page write.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* VTIME_PER_SEC comes from vmlinux.h (a BTF enum constant) */
#define IOC_PAGE_SIZE		4096
#define IOC_SECT_TO_PAGE_SHIFT	3	/* 512B sectors to 4kB pages */
#define LCOEF_RANDIO_PAGES	4096	/* 16MB seek threshold */
#define IOCOST_COST_F_MERGE	(1ULL << 0)	/* not in BTF: a plain macro */
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
 * the model never leaks or reuses stale per-cgroup state
 */
struct {
	__uint(type, BPF_MAP_TYPE_CGRP_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, __u64);
} cursor_store SEC(".maps");

SEC("struct_ops")
u64 BPF_PROG(iocost_2x_calc_cost, u64 opf, u64 nbytes, u64 sector,
	     struct blkcg *blkcg, u64 model_flags)
{
	u64 pages, seek_pages = 0, base, coef_page, randio, cost;

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
	 * mirror the builtin single per-cgroup cursor: the model keeps
	 * its own cursor keyed by the blkcg argument
	 */
	{
		__u64 *cursor, cur;

		cursor = bpf_cgrp_storage_get(&cursor_store,
					      blkcg->css.cgroup, NULL,
					      BPF_LOCAL_STORAGE_GET_F_CREATE);
		if (!cursor)
			return 2 * (base + RU(nbytes, IOC_PAGE_SIZE) * coef_page);
		cur = *cursor;
		seek_pages = sector > cur ? sector - cur : cur - sector;
		seek_pages >>= IOC_SECT_TO_PAGE_SHIFT;
		if (seek_pages > LCOEF_RANDIO_PAGES)
			base = randio;
		if (!(model_flags & IOCOST_COST_F_MERGE))
			*cursor = sector + RU(nbytes, 512);
	}

	pages = RU(nbytes, IOC_PAGE_SIZE);
	if (!pages)
		pages = 1;	/* dataless flush: one page */
	if (model_flags & IOCOST_COST_F_MERGE)
		base = 0;

	cost = 2 * (base + pages * coef_page);
	return cost;
}

SEC(".struct_ops")
struct iocost_model_ops iocost_2x = {
	.calc_cost = (void *)iocost_2x_calc_cost,
	.name = "iocost_2x",
};

char LICENSE[] SEC("license") = "GPL";
