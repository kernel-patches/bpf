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
	__bpf_md_ptr(struct page *, page);
	__bpf_md_ptr(struct page_owner *, po);
	u64 pfn;
	int nid;
};

DEFINE_BPF_ITER_FUNC(page_owner, struct bpf_iter_meta *meta,
		     struct page *page, struct page_owner *po, u64 pfn,
		     int nid)

static void *page_owner_seq_start(struct seq_file *seq, loff_t *posp)
{
	struct page_owner_scan *scan = seq->private;

	if (*posp == 0)
		scan->pfn = min_low_pfn;

	if (!page_owner_next_eligible(scan))
		return NULL;
	return scan->page;
}

static void *page_owner_seq_next(struct seq_file *seq, void *v, loff_t *posp)
{
	struct page_owner_scan *scan = seq->private;

	++*posp;
	scan->pfn++;
	if (!page_owner_next_eligible(scan))
		return NULL;

	return scan->page;
}

static int page_owner_prog_seq_show(struct bpf_prog *prog,
				    struct bpf_iter_meta *meta, void *v)
{
	struct page_owner_scan *scan = meta->seq->private;
	struct bpf_iter__page_owner ctx = {};

	ctx.meta = meta;
	if (v) {
		ctx.page = (struct page *)v;
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
	.ctx_arg_info_size	= 2,
	.ctx_arg_info		= {
		{ offsetof(struct bpf_iter__page_owner, page),
		  PTR_TO_BTF_ID_OR_NULL },
		{ offsetof(struct bpf_iter__page_owner, po),
		  PTR_TO_BTF_ID_OR_NULL },
	},
	.seq_info		= &page_owner_iter_seq_info,
};

BTF_ID_LIST(page_owner_btf_ids)
BTF_ID(struct, page)
BTF_ID(struct, page_owner)

int page_owner_iter_register(void)
{
	page_owner_iter_reg_info.ctx_arg_info[0].btf_id =
		page_owner_btf_ids[0];
	page_owner_iter_reg_info.ctx_arg_info[1].btf_id =
		page_owner_btf_ids[1];

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

	kit->scan.pfn = min_low_pfn;
	kit->scan.page = NULL;
	return 0;
}

__bpf_kfunc struct page_owner_scan *
bpf_iter_page_owner_next(struct bpf_iter_page_owner *it)
{
	struct bpf_iter_page_owner_kern *kit = (void *)it;

	cond_resched();

	if (kit->scan.page)
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
	return stack_depot_snprint(scan->po_snap.handle, buf__uninit, buf__sz,
				   0);
}

__bpf_kfunc int bpf_page_owner_get_memcg_info(struct page_owner_scan *scan,
					      struct memcg_info *info__uninit,
					      char *buf__uninit, u32 buf__sz)
{
	/* Guard against the section being offlined after scan. */
	struct page *page = pfn_to_online_page(scan->pfn);

	if (!page) {
		*info__uninit = (struct memcg_info){};
		if (buf__uninit && buf__sz)
			buf__uninit[0] = '\0';
		return -ENODATA;
	}

	return get_page_memcg_info(page, info__uninit, buf__uninit, buf__sz);
}

__bpf_kfunc_end_defs();
