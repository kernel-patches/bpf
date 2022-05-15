// SPDX-License-Identifier: GPL-2.0-only
/*
 * Functions to manage eBPF programs attached to cgroup subsystems
 *
 * Copyright 2022 Google LLC.
 */

#include <linux/bpf-rstat.h>
#include <linux/btf_ids.h>
#include <linux/cgroup.h>
#include <linux/filter.h>

static LIST_HEAD(bpf_rstat_flushers);
static DEFINE_SPINLOCK(bpf_rstat_flushers_lock);


struct bpf_rstat_flusher {
	struct bpf_prog *prog;
	/* List of BPF rtstat flushers, anchored at subsys->bpf */
	struct list_head list;
};

struct bpf_rstat_link {
	struct bpf_link link;
	struct bpf_rstat_flusher *flusher;
};

static int bpf_rstat_flush_attach(struct bpf_prog *prog,
				  struct bpf_rstat_link *rlink)
{
	struct bpf_rstat_flusher *flusher;

	flusher = kmalloc(sizeof(*flusher), GFP_KERNEL);
	if (!flusher)
		return -ENOMEM;

	flusher->prog = prog;
	rlink->flusher = flusher;

	spin_lock(&bpf_rstat_flushers_lock);
	list_add(&flusher->list, &bpf_rstat_flushers);
	spin_unlock(&bpf_rstat_flushers_lock);

	return 0;
}

static void bpf_rstat_flush_detach(struct bpf_rstat_link *rstat_link)
{
	struct bpf_rstat_flusher *flusher = rstat_link->flusher;

	if (!flusher)
		return;

	spin_lock(&bpf_rstat_flushers_lock);
	list_del(&flusher->list);
	bpf_prog_put(flusher->prog);
	kfree(flusher);
	spin_unlock(&bpf_rstat_flushers_lock);
}

static const struct bpf_func_proto *
bpf_rstat_flush_func_proto(enum bpf_func_id func_id,
			   const struct bpf_prog *prog)
{
	return bpf_base_func_proto(func_id);
}

BTF_ID_LIST_SINGLE(bpf_cgroup_btf_ids, struct, cgroup)

static bool bpf_rstat_flush_is_valid_access(int off, int size,
					    enum bpf_access_type type,
					    const struct bpf_prog *prog,
					    struct bpf_insn_access_aux *info)
{
	if (type == BPF_WRITE)
		return false;

	if (off < 0 || off + size > sizeof(struct bpf_rstat_flush_ctx))
		return false;
	/* The verifier guarantees that size > 0 */
	if (off % size != 0)
		return false;

	switch (off) {
	case bpf_ctx_range_ptr(struct bpf_rstat_flush_ctx, cgrp):
		info->reg_type = PTR_TO_BTF_ID;
		info->btf_id = bpf_cgroup_btf_ids[0];
		info->btf = bpf_get_btf_vmlinux();
		return !IS_ERR(info->btf) && info->btf && size == sizeof(__u64);
	case bpf_ctx_range_ptr(struct bpf_rstat_flush_ctx, parent):
		info->reg_type = PTR_TO_BTF_ID_OR_NULL;
		info->btf_id = bpf_cgroup_btf_ids[0];
		info->btf = bpf_get_btf_vmlinux();
		return !IS_ERR(info->btf) && info->btf && size == sizeof(__u64);
	case bpf_ctx_range(struct bpf_rstat_flush_ctx, cpu):
		return size == sizeof(__s32);
	default:
		return false;
	}
}

const struct bpf_prog_ops rstat_flush_prog_ops = {
};

const struct bpf_verifier_ops rstat_flush_verifier_ops = {
	.get_func_proto         = bpf_rstat_flush_func_proto,
	.is_valid_access        = bpf_rstat_flush_is_valid_access,
};

static void bpf_rstat_link_release(struct bpf_link *link)
{
	struct bpf_rstat_link *rlink;

	rlink = container_of(link,
			     struct bpf_rstat_link,
			     link);

	/* rstat flushers are currently the only supported rstat programs */
	bpf_rstat_flush_detach(rlink);
}

static void bpf_rstat_link_dealloc(struct bpf_link *link)
{
	struct bpf_rstat_link *rlink = container_of(link,
						    struct bpf_rstat_link,
						    link);
	kfree(rlink);
}

static const struct bpf_link_ops bpf_rstat_link_lops = {
	.release = bpf_rstat_link_release,
	.dealloc = bpf_rstat_link_dealloc,
};

int bpf_rstat_link_attach(const union bpf_attr *attr,
			  struct bpf_prog *prog)
{
	struct bpf_link_primer link_primer;
	struct bpf_rstat_link *link;
	int err;

	if (attr->link_create.target_fd || attr->link_create.flags)
		return -EINVAL;

	link = kzalloc(sizeof(*link), GFP_USER);
	if (!link)
		return -ENOMEM;

	bpf_link_init(&link->link, BPF_LINK_TYPE_RSTAT,
		      &bpf_rstat_link_lops, prog);

	err = bpf_link_prime(&link->link, &link_primer);
	if (err) {
		kfree(link);
		return err;
	}

	/* rstat flushers are currently the only supported rstat programs */
	err = bpf_rstat_flush_attach(prog, link);
	if (err) {
		bpf_link_cleanup(&link_primer);
		return err;
	}

	return bpf_link_settle(&link_primer);
}
