// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2023. Huawei Technologies Co., Ltd */
#include "bpf_iter.h"
#include <string.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

struct dump_ctx {
	struct seq_file *seq;
	struct inode *inode;
	unsigned long from;
	unsigned long max;
};

void bpf_filemap_cachestat(struct inode *inode, unsigned long from, unsigned long last,
		           struct cachestat *cs) __ksym;
long bpf_filemap_find_present(struct inode *inode, unsigned long from, unsigned long last) __ksym;
long bpf_filemap_get_order(struct inode *inode, unsigned long index) __ksym;

static u64 dump_page_order(unsigned int i, void *ctx)
{
        struct dump_ctx *dump = ctx;
	unsigned long index;
	unsigned int order;

	index = bpf_filemap_find_present(dump->inode, dump->from, dump->max);
	if (index == -1UL)
		return 1;
	order = bpf_filemap_get_order(dump->inode, index);

        BPF_SEQ_PRINTF(dump->seq, "  page offset %lu order %u\n", index, order);
	dump->from = index + (1 << order);
        return 0;
}

SEC("?iter/fs_inode")
int dump_raw_inode(struct bpf_iter__fs_inode *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct inode *inode = ctx->inode;
	struct btf_ptr ptr;

	if (inode == NULL)
		return 0;

	memset(&ptr, 0, sizeof(ptr));
	ptr.type_id = bpf_core_type_id_kernel(struct inode);
	ptr.ptr = inode;
	bpf_seq_printf_btf(seq, &ptr, sizeof(ptr), 0);

	memset(&ptr, 0, sizeof(ptr));
	ptr.type_id = bpf_core_type_id_kernel(struct super_block);
	ptr.ptr = inode->i_sb;
	bpf_seq_printf_btf(seq, &ptr, sizeof(ptr), 0);

	return 0;
}

SEC("?iter/fs_inode")
int dump_inode(struct bpf_iter__fs_inode *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct inode *inode = ctx->inode;
	struct cachestat cs = {};
	struct super_block *sb;
	struct dentry *dentry;
	struct dump_ctx dump;

	if (inode == NULL)
		return 0;

	sb = inode->i_sb;
	BPF_SEQ_PRINTF(seq, "sb: bsize %lu s_op %ps s_type %ps name %s\n",
		       sb->s_blocksize, sb->s_op, sb->s_type, sb->s_type->name);

	BPF_SEQ_PRINTF(seq, "ino: inode nlink %d inum %lu size %llu",
			inode->i_nlink, inode->i_ino, inode->i_size);
	dentry = ctx->dentry;
	if (dentry)
		BPF_SEQ_PRINTF(seq, ", name %s\n", dentry->d_name.name);
	else
		BPF_SEQ_PRINTF(seq, "\n");

	bpf_filemap_cachestat(inode, 0, ~0UL, &cs);
	BPF_SEQ_PRINTF(seq, "cache: cached %llu dirty %llu wb %llu evicted %llu\n",
			cs.nr_cache, cs.nr_dirty, cs.nr_writeback, cs.nr_evicted);

	dump.seq = seq;
	dump.inode = inode;
	dump.from = 0;
	/* TODO: handle BPF_MAX_LOOPS */
	dump.max = ((unsigned long)inode->i_size + 4095) / 4096;
	BPF_SEQ_PRINTF(seq, "orders:\n");
	bpf_loop(dump.max, dump_page_order, &dump, 0);

	return 0;
}

SEC("?iter/fs_mnt")
int dump_mnt(struct bpf_iter__fs_mnt *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct mount *mnt = ctx->mnt;
	struct super_block *sb;

	if (mnt == NULL)
		return 0;

	sb = mnt->mnt.mnt_sb;
	BPF_SEQ_PRINTF(seq, "dev %u:%u ",
		       sb->s_dev >> 20, sb->s_dev & ((1 << 20) - 1));

	BPF_SEQ_PRINTF(seq, "id %d parent_id %d mnt_flags 0x%x",
		       mnt->mnt_id, mnt->mnt_parent->mnt_id, mnt->mnt.mnt_flags);
	if (mnt->mnt.mnt_flags & 0x1000)
		BPF_SEQ_PRINTF(seq, " shared:%d", mnt->mnt_group_id);
	BPF_SEQ_PRINTF(seq, "\n");

	return 0;
}
