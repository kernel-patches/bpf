// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2021 Facebook */

#include <linux/bpf.h>
#include <linux/btf_ids.h>
#include <linux/init.h>
#include <linux/mm_types.h>
#include <linux/mnt_namespace.h>
#include <linux/nsproxy.h>
#include <linux/pagemap.h>
#include <linux/radix-tree.h>
#include <linux/seq_file.h>
#include "../../fs/mount.h"

struct bpf_iter_seq_pagecache_info {
	struct mnt_namespace *ns;
	struct radix_tree_root superblocks;
	struct super_block *cur_sb;
	struct inode *cur_inode;
	unsigned long cur_page_idx;
};

static struct super_block *goto_next_sb(struct bpf_iter_seq_pagecache_info *info)
{
	struct super_block *sb = NULL;
	struct radix_tree_iter iter;
	void **slot;

	radix_tree_for_each_slot(slot, &info->superblocks, &iter,
				 ((unsigned long)info->cur_sb + 1)) {
		sb = (struct super_block *)iter.index;
		break;
	}

	info->cur_sb = sb;
	info->cur_inode = NULL;
	info->cur_page_idx = 0;
	return sb;
}

static bool inode_unusual(struct inode *inode) {
	return ((inode->i_state & (I_FREEING|I_WILL_FREE|I_NEW)) ||
		(inode->i_mapping->nrpages == 0));
}

static struct inode *goto_next_inode(struct bpf_iter_seq_pagecache_info *info)
{
	struct inode *prev_inode = info->cur_inode;
	struct inode *inode;

retry:
	BUG_ON(!info->cur_sb);
	spin_lock(&info->cur_sb->s_inode_list_lock);

	if (!info->cur_inode) {
		list_for_each_entry(inode, &info->cur_sb->s_inodes, i_sb_list) {
			spin_lock(&inode->i_lock);
			if (inode_unusual(inode)) {
				spin_unlock(&inode->i_lock);
				continue;
			}
			__iget(inode);
			spin_unlock(&inode->i_lock);
			info->cur_inode = inode;
			break;
		}
	} else {
		inode = info->cur_inode;
		info->cur_inode = NULL;
		list_for_each_entry_continue(inode, &info->cur_sb->s_inodes,
					     i_sb_list) {
			spin_lock(&inode->i_lock);
			if (inode_unusual(inode)) {
				spin_unlock(&inode->i_lock);
				continue;
			}
			__iget(inode);
			spin_unlock(&inode->i_lock);
			info->cur_inode = inode;
			break;
		}
	}

	/* Seen all inodes in this superblock */
	if (!info->cur_inode) {
		spin_unlock(&info->cur_sb->s_inode_list_lock);
		if (!goto_next_sb(info)) {
			inode = NULL;
			goto out;
		}

		goto retry;
	}

	spin_unlock(&info->cur_sb->s_inode_list_lock);
	info->cur_page_idx = 0;
out:
	iput(prev_inode);
	return info->cur_inode;
}

static struct page *goto_next_page(struct bpf_iter_seq_pagecache_info *info)
{
	struct page *page, *ret = NULL;
	unsigned long idx;

	rcu_read_lock();
retry:
	BUG_ON(!info->cur_inode);
	ret = NULL;
	xa_for_each_start(&info->cur_inode->i_data.i_pages, idx, page,
			  info->cur_page_idx) {
		if (!page_cache_get_speculative(page))
			continue;

		ret = page;
		info->cur_page_idx = idx + 1;
		break;
	}

	if (!ret) {
		/* Seen all inodes and superblocks */
		if (!goto_next_inode(info))
			goto out;

		goto retry;
	}

out:
	rcu_read_unlock();
	return ret;
}

static void *pagecache_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct bpf_iter_seq_pagecache_info *info = seq->private;
	struct page *page;

	if (!info->cur_sb && !goto_next_sb(info))
		return NULL;
	if (!info->cur_inode && !goto_next_inode(info))
		return NULL;

	page = goto_next_page(info);
	if (!page)
		return NULL;

	if (*pos == 0)
		++*pos;

	return page;

}

static void *pagecache_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct bpf_iter_seq_pagecache_info *info = seq->private;
	struct page *page;

	++*pos;
	put_page((struct page *)v);
	page = goto_next_page(info);
	if (!page)
		return NULL;

	return page;
}

struct bpf_iter__pagecache {
	__bpf_md_ptr(struct bpf_iter_meta *, meta);
	__bpf_md_ptr(struct page *, page);
};

DEFINE_BPF_ITER_FUNC(pagecache, struct bpf_iter_meta *meta, struct page *page)

static int __pagecache_seq_show(struct seq_file *seq, struct page *page,
				bool in_stop)
{
	struct bpf_iter_meta meta;
	struct bpf_iter__pagecache ctx;
	struct bpf_prog *prog;

	meta.seq = seq;
	prog = bpf_iter_get_info(&meta, in_stop);
	if (!prog)
		return 0;

	meta.seq = seq;
	ctx.meta = &meta;
	ctx.page = page;
	return bpf_iter_run_prog(prog, &ctx);
}

static int pagecache_seq_show(struct seq_file *seq, void *v)
{
	return __pagecache_seq_show(seq, v, false);
}

static void pagecache_seq_stop(struct seq_file *seq, void *v)
{
	(void)__pagecache_seq_show(seq, v, true);
	if (v)
		put_page((struct page *)v);
}

static int init_seq_pagecache(void *priv_data, struct bpf_iter_aux_info *aux)
{
	struct bpf_iter_seq_pagecache_info *info = priv_data;
	struct radix_tree_iter iter;
	struct super_block *sb;
	struct mount *mnt;
	void **slot;
	int err;

	info->ns = current->nsproxy->mnt_ns;
	get_mnt_ns(info->ns);
	INIT_RADIX_TREE(&info->superblocks, GFP_KERNEL);

	spin_lock(&info->ns->ns_lock);
	list_for_each_entry(mnt, &info->ns->list, mnt_list) {
		sb = mnt->mnt.mnt_sb;

		/* The same mount may be mounted in multiple places */
		if (radix_tree_lookup(&info->superblocks, (unsigned long)sb))
			continue;

		err = radix_tree_insert(&info->superblocks,
				        (unsigned long)sb, (void *)1);
		if (err)
			goto out;
	}

	radix_tree_for_each_slot(slot, &info->superblocks, &iter, 0) {
		sb = (struct super_block *)iter.index;
		atomic_inc(&sb->s_active);
	}

	err = 0;
out:
	spin_unlock(&info->ns->ns_lock);
	return err;
}

static void fini_seq_pagecache(void *priv_data)
{
	struct bpf_iter_seq_pagecache_info *info = priv_data;
	struct radix_tree_iter iter;
	struct super_block *sb;
	void **slot;

	radix_tree_for_each_slot(slot, &info->superblocks, &iter, 0) {
		sb = (struct super_block *)iter.index;
		atomic_dec(&sb->s_active);
		radix_tree_delete(&info->superblocks, iter.index);
	}

	put_mnt_ns(info->ns);
}

static const struct seq_operations pagecache_seq_ops = {
	.start	= pagecache_seq_start,
	.next	= pagecache_seq_next,
	.stop	= pagecache_seq_stop,
	.show	= pagecache_seq_show,
};

static const struct bpf_iter_seq_info pagecache_seq_info = {
	.seq_ops		= &pagecache_seq_ops,
	.init_seq_private	= init_seq_pagecache,
	.fini_seq_private	= fini_seq_pagecache,
	.seq_priv_size		= sizeof(struct bpf_iter_seq_pagecache_info),
};

static struct bpf_iter_reg pagecache_reg_info = {
	.target			= "pagecache",
	.ctx_arg_info_size	= 1,
	.ctx_arg_info		= {
		{ offsetof(struct bpf_iter__pagecache, page),
		  PTR_TO_BTF_ID_OR_NULL },
	},
	.seq_info		= &pagecache_seq_info,
};

BTF_ID_LIST(btf_page_id)
BTF_ID(struct, page)

static int __init bpf_pagecache_iter_init(void)
{
	pagecache_reg_info.ctx_arg_info[0].btf_id = *btf_page_id;
	return bpf_iter_reg_target(&pagecache_reg_info);
}

late_initcall(bpf_pagecache_iter_init);
