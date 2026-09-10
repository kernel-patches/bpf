// SPDX-License-Identifier: GPL-2.0
/*
 * Example multi-stream sequentiality detection cost model.
 *
 * The builtin model keeps a single cursor per cgroup, so two
 * interleaved sequential readers in one cgroup are all priced random
 * (measured 89x overcharge, 12.9x throughput collapse), while random
 * IO inside a hot window smaller than the 16MB seek threshold is
 * priced sequential (measured 107x undercharge).  This model replaces
 * the single cursor with a per-cgroup table of stream slots: an IO is
 * sequential iff its sector matches the expected next sector of any
 * tracked stream.  Interleaved streams keep their own slots, and
 * windowed random IO rarely matches a moving expectation.
 *
 * Stream state lives in a CGRP_STORAGE map, so it is created and
 * freed with the cgroup.  The model implements the full builtin
 * linear formula itself, including flush pricing.
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

#define NSLOTS	4

struct streams {
	__u64 expected[NSLOTS];	/* next expected sector, per stream */
	__u64 stamp[NSLOTS];	/* LRU stamp, 0 = empty */
};

/*
 * per-cgroup stream table: keyed by the cgroup, freed with it
 */
struct {
	__uint(type, BPF_MAP_TYPE_CGRP_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct streams);
} stream_tab SEC(".maps");

SEC("struct_ops")
u64 BPF_PROG(iocost_ms_calc_cost, u64 opf, u64 nbytes, u64 sector,
	     struct blkcg *blkcg, u64 model_flags)
{
	struct streams *s;
	u64 pages, base, coef_page, randio, advance, now;
	u32 i, victim = 0, found = 0xFFFFFFFF;

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
	advance = RU(nbytes, 512);	/* sectors */

	s = bpf_cgrp_storage_get(&stream_tab, blkcg->css.cgroup, NULL,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!s)
		return base + RU(nbytes, IOC_PAGE_SIZE) * coef_page;

	now = bpf_ktime_get_ns();
	for (i = 0; i < NSLOTS; i++) {
		if (s->expected[i] == sector && s->stamp[i]) {
			found = i;
			break;
		}
	}
	if (found != 0xFFFFFFFF) {
		/* sequential: keep the seq base from the op branch */
		s->expected[found] = sector + advance;
		s->stamp[found] = now;
	} else {
		base = randio;
		for (i = 1; i < NSLOTS; i++) {
			if (s->stamp[i] < s->stamp[victim])
				victim = i;
		}
		s->expected[victim] = sector + advance;
		s->stamp[victim] = now;
	}

	pages = RU(nbytes, IOC_PAGE_SIZE);
	if (!pages)
		pages = 1;	/* dataless flush: one page */
	if (model_flags & IOCOST_COST_F_MERGE) {
		/*
		 * merged bios skip the base cost but still advance
		 * the stream position above, so a merge at the
		 * expected sector does not make the following new IO
		 * look random
		 */
		base = 0;
	}

	return base + pages * coef_page;
}

SEC(".struct_ops")
struct iocost_model_ops iocost_ms = {
	.calc_cost = (void *)iocost_ms_calc_cost,
	.name = "iocost_ms",
};

char LICENSE[] SEC("license") = "GPL";
