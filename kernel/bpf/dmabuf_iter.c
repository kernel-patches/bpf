// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2025 Google LLC */
#include <linux/bpf.h>
#include <linux/btf_ids.h>
#include <linux/dma-buf.h>
#include <linux/kernel.h>
#include <linux/seq_file.h>

BTF_ID_LIST_GLOBAL_SINGLE(bpf_dmabuf_btf_id, struct, dma_buf)
DEFINE_BPF_ITER_FUNC(dmabuf, struct bpf_iter_meta *meta, struct dma_buf *dmabuf)

static void *dmabuf_iter_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct dma_buf *dmabuf, *ret = NULL;

	if (*pos) {
		*pos = 0;
		return NULL;
	}
	/* Look for the first buffer we can obtain a reference to.
	 * The list mutex does not protect a dmabuf's refcount, so it can be
	 * zeroed while we are iterating. Therefore we cannot call get_dma_buf()
	 * since the caller of this program may not already own a reference to
	 * the buffer.
	 */
	mutex_lock(&dmabuf_debugfs_list_mutex);
	list_for_each_entry(dmabuf, &dmabuf_debugfs_list, list_node) {
		if (file_ref_get(&dmabuf->file->f_ref)) {
			ret = dmabuf;
			break;
		}
	}
	mutex_unlock(&dmabuf_debugfs_list_mutex);

	return ret;
}

static void *dmabuf_iter_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct dma_buf *dmabuf = v, *ret = NULL;

	++*pos;

	mutex_lock(&dmabuf_debugfs_list_mutex);
	dma_buf_put(dmabuf);
	while (!list_is_last(&dmabuf->list_node, &dmabuf_debugfs_list)) {
		dmabuf = list_next_entry(dmabuf, list_node);
		if (file_ref_get(&dmabuf->file->f_ref)) {
			ret = dmabuf;
			break;
		}
	}
	mutex_unlock(&dmabuf_debugfs_list_mutex);

	return ret;
}

struct bpf_iter__dmabuf {
	__bpf_md_ptr(struct bpf_iter_meta *, meta);
	__bpf_md_ptr(struct dma_buf *, dmabuf);
};

static int __dmabuf_seq_show(struct seq_file *seq, void *v, bool in_stop)
{
	struct bpf_iter_meta meta = {
		.seq = seq,
	};
	struct bpf_iter__dmabuf ctx = {
		.meta = &meta,
		.dmabuf = v,
	};
	struct bpf_prog *prog = bpf_iter_get_info(&meta, in_stop);

	if (prog)
		return bpf_iter_run_prog(prog, &ctx);

	return 0;
}

static int dmabuf_iter_seq_show(struct seq_file *seq, void *v)
{
	return __dmabuf_seq_show(seq, v, false);
}

static void dmabuf_iter_seq_stop(struct seq_file *seq, void *v)
{
	struct dma_buf *dmabuf = v;

	if (dmabuf)
		dma_buf_put(dmabuf);
}

static const struct seq_operations dmabuf_iter_seq_ops = {
	.start	= dmabuf_iter_seq_start,
	.next	= dmabuf_iter_seq_next,
	.stop	= dmabuf_iter_seq_stop,
	.show	= dmabuf_iter_seq_show,
};

static void bpf_iter_dmabuf_show_fdinfo(const struct bpf_iter_aux_info *aux,
					struct seq_file *seq)
{
	seq_puts(seq, "dmabuf iter\n");
}

static const struct bpf_iter_seq_info dmabuf_iter_seq_info = {
	.seq_ops		= &dmabuf_iter_seq_ops,
	.init_seq_private	= NULL,
	.fini_seq_private	= NULL,
	.seq_priv_size		= 0,
};

static struct bpf_iter_reg bpf_dmabuf_reg_info = {
	.target			= "dmabuf",
	.show_fdinfo		= bpf_iter_dmabuf_show_fdinfo,
	.ctx_arg_info_size	= 1,
	.ctx_arg_info		= {
		{ offsetof(struct bpf_iter__dmabuf, dmabuf),
		  PTR_TO_BTF_ID_OR_NULL },
	},
	.seq_info		= &dmabuf_iter_seq_info,
};

static int __init dmabuf_iter_init(void)
{
	bpf_dmabuf_reg_info.ctx_arg_info[0].btf_id = bpf_dmabuf_btf_id[0];
	return bpf_iter_reg_target(&bpf_dmabuf_reg_info);
}

late_initcall(dmabuf_iter_init);
