// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2022 Google */
#include <linux/bpf.h>
#include <linux/fs.h>
#include <linux/filter.h>
#include <linux/kernel.h>
#include <linux/btf_ids.h>
#include <linux/cgroup.h>
#include <linux/kernfs.h>
#include "inode.h"

static void *cgroup_view_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct bpf_dir_tag *tag;
	struct kernfs_node *kn;
	struct cgroup *cgroup;
	struct inode *dir;

	/* Only one session is supported. */
	if (*pos > 0)
		return NULL;

	dir = d_inode(seq->file->f_path.dentry->d_parent);
	tag = dir->i_private;
	if (!tag)
		return NULL;

	kn = tag->private;

	rcu_read_lock();
	cgroup = rcu_dereference(*(void __rcu __force **)&kn->priv);
	if (!cgroup || !cgroup_tryget(cgroup))
		cgroup = NULL;
	rcu_read_unlock();

	if (!cgroup)
		return NULL;

	if (*pos == 0)
		++*pos;
	return cgroup;
}

static void *cgroup_view_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	++*pos;
	return NULL;
}

struct bpf_iter__cgroup_view {
	__bpf_md_ptr(struct bpf_iter_meta *, meta);
	__bpf_md_ptr(struct cgroup *, cgroup);
};

DEFINE_BPF_ITER_FUNC(cgroup_view, struct bpf_iter_meta *meta, struct cgroup *cgroup)

static int cgroup_view_seq_show(struct seq_file *seq, void *v)
{
	struct bpf_iter__cgroup_view ctx;
	struct bpf_iter_meta meta;
	struct bpf_prog *prog;
	int ret = 0;

	ctx.meta = &meta;
	ctx.cgroup = v;
	meta.seq = seq;
	prog = bpf_iter_get_info(&meta, false);
	if (prog)
		ret = bpf_iter_run_prog(prog, &ctx);

	return ret;
}

static void cgroup_view_seq_stop(struct seq_file *seq, void *v)
{
	if (v)
		cgroup_put(v);
}

static const struct seq_operations cgroup_view_seq_ops = {
	.start	= cgroup_view_seq_start,
	.next	= cgroup_view_seq_next,
	.stop	= cgroup_view_seq_stop,
	.show	= cgroup_view_seq_show,
};

BTF_ID_LIST(btf_cgroup_id)
BTF_ID(struct, cgroup)

static const struct bpf_iter_seq_info cgroup_view_seq_info = {
	.seq_ops		= &cgroup_view_seq_ops,
	.init_seq_private	= NULL,
	.fini_seq_private	= NULL,
	.seq_priv_size		= 0,
};

static struct bpf_iter_reg cgroup_view_reg_info = {
	.target			= "cgroup_view",
	.feature		= BPF_ITER_INHERIT,
	.ctx_arg_info_size	= 1,
	.ctx_arg_info		= {
		{ offsetof(struct bpf_iter__cgroup_view, cgroup),
		  PTR_TO_BTF_ID },
	},
	.seq_info		= &cgroup_view_seq_info,
};

static int __init cgroup_view_init(void)
{
	cgroup_view_reg_info.ctx_arg_info[0].btf_id = *btf_cgroup_id;
	return bpf_iter_reg_target(&cgroup_view_reg_info);
}

late_initcall(cgroup_view_init);
