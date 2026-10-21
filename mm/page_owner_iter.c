// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/btf_ids.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/seq_file.h>
#include <linux/stackdepot.h>

#include "page_owner.h"

struct bpf_iter__page_owner {
	__bpf_md_ptr(struct bpf_iter_meta *, meta);
	__bpf_md_ptr(struct page_owner *, po);
	u64 pfn;
	int nid;
};

DEFINE_BPF_ITER_FUNC(page_owner, struct bpf_iter_meta *meta,
		     struct page_owner *po, u64 pfn, int nid)

static void *page_owner_seq_start(struct seq_file *seq, loff_t *posp)
{
	struct page_owner_scan *scan = seq->private;

	if (*posp == 0)
		scan->pfn = min_low_pfn;

	if (!page_owner_next_eligible(scan))
		return NULL;
	return &scan->po_snap;
}

static void *page_owner_seq_next(struct seq_file *seq, void *v, loff_t *posp)
{
	struct page_owner_scan *scan = seq->private;

	++*posp;
	scan->pfn++;
	if (!page_owner_next_eligible(scan))
		return NULL;

	return &scan->po_snap;
}

static int page_owner_prog_seq_show(struct bpf_prog *prog,
				    struct bpf_iter_meta *meta, void *v)
{
	struct page_owner_scan *scan = meta->seq->private;
	struct bpf_iter__page_owner ctx = {};

	ctx.meta = meta;
	if (v) {
		/* @po: hit-time snapshot, no RCU window needed. */
		ctx.po = &scan->po_snap;
		ctx.pfn = scan->pfn;
		ctx.nid = scan->nid;
	}

	return bpf_iter_run_prog(prog, &ctx);
}

static int page_owner_seq_show(struct seq_file *seq, void *v)
{
	struct bpf_iter_meta meta;
	struct bpf_prog *prog;

	meta.seq = seq;
	prog = bpf_iter_get_info(&meta, false);
	if (!prog)
		return 0;

	return page_owner_prog_seq_show(prog, &meta, v);
}

static void page_owner_seq_stop(struct seq_file *seq, void *v)
{
	if (!v) {
		struct bpf_iter_meta meta = { .seq = seq };
		struct bpf_prog *prog;

		prog = bpf_iter_get_info(&meta, true);
		if (prog)
			page_owner_prog_seq_show(prog, &meta, NULL);
	}
}

static const struct seq_operations page_owner_iter_seq_ops = {
	.start	= page_owner_seq_start,
	.next	= page_owner_seq_next,
	.stop	= page_owner_seq_stop,
	.show	= page_owner_seq_show,
};

static const struct bpf_iter_seq_info page_owner_iter_seq_info = {
	.seq_ops		= &page_owner_iter_seq_ops,
	.init_seq_private	= NULL,
	.fini_seq_private	= NULL,
	.seq_priv_size		= sizeof(struct page_owner_scan),
};

static struct bpf_iter_reg page_owner_iter_reg_info = {
	.target			= "page_owner",
	.ctx_arg_info_size	= 1,
	.ctx_arg_info		= {
		{ offsetof(struct bpf_iter__page_owner, po),
		  PTR_TO_BTF_ID_OR_NULL },
	},
	.seq_info		= &page_owner_iter_seq_info,
	.feature		= BPF_ITER_RESCHED,
};

BTF_ID_LIST(page_owner_btf_ids)
BTF_ID(struct, page_owner)

int page_owner_iter_register(void)
{
	page_owner_iter_reg_info.ctx_arg_info[0].btf_id =
		page_owner_btf_ids[0];

	return bpf_iter_reg_target(&page_owner_iter_reg_info);
}

/* opaque to BPF programs */
struct bpf_iter_page_owner {
	__u64 __opaque[16];
} __attribute__((aligned(8)));

struct bpf_iter_page_owner_kern {
	struct page_owner_scan scan;
} __attribute__((aligned(8)));

__bpf_kfunc_start_defs();

__bpf_kfunc int bpf_iter_page_owner_new(struct bpf_iter_page_owner *it)
{
	struct bpf_iter_page_owner_kern *kit = (void *)it;

	BUILD_BUG_ON(sizeof(*kit) > sizeof(*it));
	BUILD_BUG_ON(__alignof__(*kit) != __alignof__(*it));

	kit->scan.pfn = min_low_pfn - 1;
	return 0;
}

__bpf_kfunc struct page_owner_scan *
bpf_iter_page_owner_next(struct bpf_iter_page_owner *it)
{
	struct bpf_iter_page_owner_kern *kit = (void *)it;

	if (!static_branch_unlikely(&page_owner_inited))
		return NULL;

	cond_resched();

	kit->scan.pfn++;
	if (!page_owner_next_eligible(&kit->scan))
		return NULL;

	return &kit->scan;
}

__bpf_kfunc void bpf_iter_page_owner_destroy(struct bpf_iter_page_owner *it)
{
}

__bpf_kfunc int bpf_page_owner_stack_snprint(struct page_owner_scan *scan,
					     char *buf__uninit, u32 buf__sz)
{
	int len = 0;

	if (!buf__uninit || !buf__sz)
		return 0;

	if (static_branch_unlikely(&page_owner_inited))
		len = stack_depot_snprint(scan->po_snap.handle, buf__uninit,
					  buf__sz, 0);

	if (!len)
		buf__uninit[0] = '\0';

	return len;
}

/**
 * bpf_page_owner_get_memcg_info - Report the memcg charged for the current page
 * @scan: page_owner scan handle.
 * @info__uninit: output buffer for the memcg_info.
 * @buf__uninit: optional output buffer for the full cgroup path.
 * @buf__sz: size of @buf__uninit.
 *
 * Fills @info__uninit with the memcg charged for the page backing
 * @scan->pfn.  If @buf__uninit and @buf__sz are provided, the full
 * cgroup path is also copied out, so a BPF program can attribute a
 * page_owner allocation to a specific cgroup.
 *
 * @scan->pfn is resolved to a struct page under get_online_mems(),
 * so the page cannot be accessed after its memory section is offlined
 * or removed.
 *
 * Returns:
 * * 0 on success
 * * -ENODATA if the page is not online or not charged to a memcg
 * * -EOPNOTSUPP if built without CONFIG_MEMCG
 */
__bpf_kfunc int bpf_page_owner_get_memcg_info(struct page_owner_scan *scan,
					      struct memcg_info *info__uninit,
					      char *buf__uninit, u32 buf__sz)
{
	struct page *page;
	int ret = -ENODATA;

	if (!static_branch_unlikely(&page_owner_inited))
		goto nodata;

	get_online_mems();
	page = pfn_to_online_page(scan->pfn);
	if (!page) {
		put_online_mems();
		goto nodata;
	}
	ret = get_page_memcg_info(page, info__uninit, buf__uninit, buf__sz);
	put_online_mems();
	return ret;

nodata:
	*info__uninit = (struct memcg_info){};
	if (buf__uninit && buf__sz)
		buf__uninit[0] = '\0';
	return ret;
}

__bpf_kfunc_end_defs();
