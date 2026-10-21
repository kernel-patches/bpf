// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/btf_ids.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/seq_file.h>

#include "page_owner.h"

struct bpf_iter__page_owner {
	__bpf_md_ptr(struct bpf_iter_meta *, meta);
	__bpf_md_ptr(struct page_owner *, po);
	u64 pfn;
};

DEFINE_BPF_ITER_FUNC(page_owner, struct bpf_iter_meta *meta,
		     struct page_owner *po, u64 pfn)

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
