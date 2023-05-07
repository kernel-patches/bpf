// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023. Huawei Technologies Co., Ltd
 */
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/seq_file.h>

/* TODO: move fs_iter.c to fs directory ? */
#include "../../fs/mount.h"

DEFINE_BPF_ITER_FUNC(fs_inode, struct bpf_iter_meta *meta, struct inode *inode, struct dentry *dentry);
DEFINE_BPF_ITER_FUNC(fs_mnt, struct bpf_iter_meta *meta, struct mount *mnt);

struct bpf_iter__fs_inode {
	__bpf_md_ptr(struct bpf_iter_meta *, meta);
	__bpf_md_ptr(struct inode *, inode);
	__bpf_md_ptr(struct dentry *, dentry);
};

struct bpf_iter__fs_mnt {
	__bpf_md_ptr(struct bpf_iter_meta *, meta);
	__bpf_md_ptr(struct mount *, mnt);
};

struct bpf_fs_iter_aux_info {
	atomic_t count;
	enum bpf_fs_iter_type type;
	struct file *filp;
};

struct bpf_iter_seq_fs_info {
	struct bpf_fs_iter_aux_info *fs;
};

static inline void bpf_fs_iter_get(struct bpf_fs_iter_aux_info *fs)
{
	atomic_inc(&fs->count);
}

static void bpf_fs_iter_put(struct bpf_fs_iter_aux_info *fs)
{
	if (!atomic_dec_and_test(&fs->count))
		return;

	fput(fs->filp);
	kfree(fs);
}

static int bpf_iter_attach_fs(struct bpf_prog *prog, union bpf_iter_link_info *linfo,
			      struct bpf_iter_aux_info *aux)
{
	struct bpf_fs_iter_aux_info *fs;
	struct file *filp;

	if (linfo->fs.type > BPF_FS_ITER_MNT)
		return -EINVAL;
	/* TODO: The file-system is pinned */
	filp = fget(linfo->fs.fd);
	if (!filp)
		return -EINVAL;

	fs = kmalloc(sizeof(*fs), GFP_KERNEL);
	if (!fs) {
		fput(filp);
		return -ENOMEM;
	}

	atomic_set(&fs->count, 1);
	fs->type = linfo->fs.type;
	fs->filp = filp;
	aux->fs = fs;

	return 0;
}

static void bpf_iter_detach_fs(struct bpf_iter_aux_info *aux)
{
	bpf_fs_iter_put(aux->fs);
}

static int bpf_iter_init_seq_fs_priv(void *priv, struct bpf_iter_aux_info *aux)
{
	struct bpf_iter_seq_fs_info *info = priv;
	struct bpf_fs_iter_aux_info *fs = aux->fs;

	/* link fd is still alive, so it is OK to inc ref-count directly */
	bpf_fs_iter_get(fs);
	info->fs = fs;

	return 0;
}

static void bpf_iter_fini_seq_fs_priv(void *priv)
{
	struct bpf_iter_seq_fs_info *info = priv;

	bpf_fs_iter_put(info->fs);
}

static void *fs_iter_seq_start(struct seq_file *m, loff_t *pos)
{
	struct bpf_iter_seq_fs_info *info = m->private;

	if (*pos == 0)
		++*pos;

	if (info->fs->type == BPF_FS_ITER_INODE)
		return file_inode(info->fs->filp);
	return real_mount(info->fs->filp->f_path.mnt);
}

static int __fs_iter_seq_show(struct seq_file *m, void *v, bool stop)
{
	struct bpf_iter_seq_fs_info *info = m->private;
	struct bpf_iter_meta meta;
	struct bpf_prog *prog;
	int err;

	meta.seq = m;
	prog = bpf_iter_get_info(&meta, stop);
	if (!prog)
		return 0;

	if (info->fs->type == BPF_FS_ITER_INODE) {
		struct bpf_iter__fs_inode ino_ctx;

		ino_ctx.meta = &meta;
		ino_ctx.inode = v;
		ino_ctx.dentry = v ? d_find_alias(v) : NULL;
		err = bpf_iter_run_prog(prog, &ino_ctx);
		dput(ino_ctx.dentry);
	} else {
		struct bpf_iter__fs_mnt mnt_ctx;

		mnt_ctx.meta = &meta;
		mnt_ctx.mnt = v;
		err = bpf_iter_run_prog(prog, &mnt_ctx);
	}
	return err;
}

static void fs_iter_seq_stop(struct seq_file *m, void *v)
{
	if (!v)
		__fs_iter_seq_show(m, NULL, true);
}

static void *fs_iter_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	++*pos;
	return NULL;
}

static int fs_iter_seq_show(struct seq_file *m, void *v)
{
	return __fs_iter_seq_show(m, v, false);
}

static const struct seq_operations fs_iter_seq_ops = {
	.start = fs_iter_seq_start,
	.stop = fs_iter_seq_stop,
	.next = fs_iter_seq_next,
	.show = fs_iter_seq_show,
};

static const struct bpf_iter_seq_info fs_iter_seq_info = {
	.seq_ops = &fs_iter_seq_ops,
	.init_seq_private = bpf_iter_init_seq_fs_priv,
	.fini_seq_private = bpf_iter_fini_seq_fs_priv,
	.seq_priv_size = sizeof(struct bpf_iter_seq_fs_info),
};

static struct bpf_iter_reg fs_inode_reg_info = {
	.target = "fs_inode",
	.attach_target = bpf_iter_attach_fs,
	.detach_target = bpf_iter_detach_fs,
	.ctx_arg_info_size = 2,
	.ctx_arg_info = {
		{ offsetof(struct bpf_iter__fs_inode, inode), PTR_TO_BTF_ID_OR_NULL },
		{ offsetof(struct bpf_iter__fs_inode, dentry), PTR_TO_BTF_ID_OR_NULL },
	},
	.seq_info = &fs_iter_seq_info,
};

static struct bpf_iter_reg fs_mnt_reg_info = {
	.target = "fs_mnt",
	.attach_target = bpf_iter_attach_fs,
	.detach_target = bpf_iter_detach_fs,
	.ctx_arg_info_size = 1,
	.ctx_arg_info = {
		{ offsetof(struct bpf_iter__fs_mnt, mnt), PTR_TO_BTF_ID_OR_NULL },
	},
	.seq_info = &fs_iter_seq_info,
};

static int __init fs_iter_init(void)
{
	int err;

	fs_inode_reg_info.ctx_arg_info[0].btf_id = btf_tracing_ids[BTF_TRACING_TYPE_INODE];
	fs_inode_reg_info.ctx_arg_info[1].btf_id = btf_tracing_ids[BTF_TRACING_TYPE_DENTRY];
	err = bpf_iter_reg_target(&fs_inode_reg_info);
	if (err)
		return err;

	fs_mnt_reg_info.ctx_arg_info[0].btf_id = btf_tracing_ids[BTF_TRACING_TYPE_MOUNT];
	err = bpf_iter_reg_target(&fs_mnt_reg_info);
	if (err)
		bpf_iter_unreg_target(&fs_inode_reg_info);
	return err;
}
late_initcall(fs_iter_init);
