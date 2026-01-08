// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Google LLC */
#include <linux/bpf.h>
#include <linux/btf_ids.h>
#include <linux/kernel.h>
#include <linux/pm_wakeup.h>
#include <linux/seq_file.h>

struct bpf_iter__wakeup_source {
	__bpf_md_ptr(struct bpf_iter_meta *, meta);
	__bpf_md_ptr(struct wakeup_source *, wakeup_source);
};

static void *wakeup_source_iter_seq_start(struct seq_file *seq, loff_t *pos)
{
	int *srcuidx = seq->private;
	struct wakeup_source *ws;
	loff_t i;

	*srcuidx = wakeup_sources_read_lock();

	ws = wakeup_sources_walk_start();
	for (i = 0; ws && i < *pos; i++)
		ws = wakeup_sources_walk_next(ws);

	return ws;
}

static void *wakeup_source_iter_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct wakeup_source *ws = v;

	++*pos;

	return wakeup_sources_walk_next(ws);
}

static void wakeup_source_iter_seq_stop(struct seq_file *seq, void *v)
{
	int *srcuidx = seq->private;

	if (*srcuidx >= 0)
		wakeup_sources_read_unlock(*srcuidx);
	*srcuidx = -1;
}

static int __wakeup_source_seq_show(struct seq_file *seq, void *v, bool in_stop)
{
	struct bpf_iter_meta meta = {
		.seq = seq,
	};
	struct bpf_iter__wakeup_source ctx = {
		.meta = &meta,
		.wakeup_source = v,
	};
	struct bpf_prog *prog = bpf_iter_get_info(&meta, in_stop);

	if (prog)
		return bpf_iter_run_prog(prog, &ctx);

	return 0;
}

static int wakeup_source_iter_seq_show(struct seq_file *seq, void *v)
{
	return __wakeup_source_seq_show(seq, v, false);
}

static const struct seq_operations wakeup_source_iter_seq_ops = {
	.start	= wakeup_source_iter_seq_start,
	.next	= wakeup_source_iter_seq_next,
	.stop	= wakeup_source_iter_seq_stop,
	.show	= wakeup_source_iter_seq_show,
};

static const struct bpf_iter_seq_info wakeup_source_iter_seq_info = {
	.seq_ops		= &wakeup_source_iter_seq_ops,
	.seq_priv_size		= sizeof(int),
};

static struct bpf_iter_reg bpf_wakeup_source_reg_info = {
	.target			= "wakeup_source",
	.ctx_arg_info_size	= 1,
	.ctx_arg_info		= {
		{
			offsetof(struct bpf_iter__wakeup_source, wakeup_source),
			PTR_TO_BTF_ID_OR_NULL
		},
	},
	.seq_info		= &wakeup_source_iter_seq_info,
};

struct bpf_iter_wakeup_source {
	struct wakeup_source *ws;
	int srcuidx;
};

__bpf_kfunc_start_defs();

__bpf_kfunc int bpf_iter_wakeup_source_new(struct bpf_iter_wakeup_source *it)
{
	it->srcuidx = wakeup_sources_read_lock();
	it->ws = wakeup_sources_walk_start();

	return 0;
}

__bpf_kfunc struct wakeup_source *bpf_iter_wakeup_source_next(struct bpf_iter_wakeup_source *it)
{
	struct wakeup_source *prev = it->ws;

	if (!prev)
		return NULL;

	it->ws = wakeup_sources_walk_next(it->ws);

	return prev;
}

__bpf_kfunc void bpf_iter_wakeup_source_destroy(struct bpf_iter_wakeup_source *it)
{
	wakeup_sources_read_unlock(it->srcuidx);
}

__bpf_kfunc_end_defs();

DEFINE_BPF_ITER_FUNC(wakeup_source, struct bpf_iter_meta *meta,
		     struct wakeup_source *wakeup_source)
BTF_ID_LIST_SINGLE(bpf_wakeup_source_btf_id, struct, wakeup_source)

static int __init wakeup_source_iter_init(void)
{
	bpf_wakeup_source_reg_info.ctx_arg_info[0].btf_id = bpf_wakeup_source_btf_id[0];
	return bpf_iter_reg_target(&bpf_wakeup_source_reg_info);
}

late_initcall(wakeup_source_iter_init);
