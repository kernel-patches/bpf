// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf.h>
#include <linux/btf_ids.h>
#include <linux/cgroup.h>
#include <linux/filter.h>
#include "bpf_view.h"

static struct list_head targets = LIST_HEAD_INIT(targets);

/* bpf_view_link operations */

struct bpf_view_target_info {
	struct list_head list;
	const char *target;
	u32 ctx_arg_info_size;
	struct bpf_ctx_arg_aux ctx_arg_info[BPF_VIEW_CTX_ARG_MAX];
	u32 btf_id;
};

struct bpf_view_link {
	struct bpf_link link;
	struct bpf_view_target_info *tinfo;
};

static void bpf_view_link_release(struct bpf_link *link)
{
}

static void bpf_view_link_dealloc(struct bpf_link *link)
{
	struct bpf_view_link *view_link =
		container_of(link, struct bpf_view_link, link);
	kfree(view_link);
}

static void bpf_view_link_show_fdinfo(const struct bpf_link *link,
				      struct seq_file *seq)
{
	struct bpf_view_link *view_link =
		container_of(link, struct bpf_view_link, link);

	seq_printf(seq, "attach_target:\t%s\n", view_link->tinfo->target);
}

static const struct bpf_link_ops bpf_view_link_lops = {
	.release = bpf_view_link_release,
	.dealloc = bpf_view_link_dealloc,
	.show_fdinfo = bpf_view_link_show_fdinfo,
};

bool bpf_link_is_view(struct bpf_link *link)
{
	return link->ops == &bpf_view_link_lops;
}

int bpf_view_link_attach(const union bpf_attr *attr, bpfptr_t uattr,
			 struct bpf_prog *prog)
{
	struct bpf_link_primer link_primer;
	struct bpf_view_target_info *tinfo;
	struct bpf_view_link *link;
	u32 prog_btf_id;
	bool existed = false;
	int err;

	prog_btf_id = prog->aux->attach_btf_id;
	list_for_each_entry(tinfo, &targets, list) {
		if (tinfo->btf_id == prog_btf_id) {
			existed = true;
			break;
		}
	}
	if (!existed)
		return -ENOENT;

	link = kzalloc(sizeof(*link), GFP_USER | __GFP_NOWARN);
	if (!link)
		return -ENOMEM;

	bpf_link_init(&link->link, BPF_LINK_TYPE_VIEW, &bpf_view_link_lops, prog);
	link->tinfo = tinfo;
	err = bpf_link_prime(&link->link, &link_primer);
	if (err) {
		kfree(link);
		return err;
	}

	return bpf_link_settle(&link_primer);
}

int run_view_prog(struct bpf_prog *prog, void *ctx)
{
	int ret;

	rcu_read_lock();
	migrate_disable();
	ret = bpf_prog_run(prog, ctx);
	migrate_enable();
	rcu_read_unlock();

	return ret;
}

bool bpf_view_prog_supported(struct bpf_prog *prog)
{
	const char *attach_fname = prog->aux->attach_func_name;
	const char *prefix = BPF_VIEW_FUNC_PREFIX;
	u32 prog_btf_id = prog->aux->attach_btf_id;
	struct bpf_view_target_info *tinfo;
	int prefix_len = strlen(prefix);
	bool supported = false;

	if (strncmp(attach_fname, prefix, prefix_len))
		return false;

	list_for_each_entry(tinfo, &targets, list) {
		if (tinfo->btf_id && tinfo->btf_id == prog_btf_id) {
			supported = true;
			break;
		}
		if (!strcmp(attach_fname + prefix_len, tinfo->target)) {
			tinfo->btf_id = prog->aux->attach_btf_id;
			supported = true;
			break;
		}
	}
	if (supported) {
		prog->aux->ctx_arg_info_size = tinfo->ctx_arg_info_size;
		prog->aux->ctx_arg_info = tinfo->ctx_arg_info;
	}
	return supported;
}

/* Generate BTF_IDs */
BTF_ID_LIST(bpf_view_btf_ids)
BTF_ID(struct, seq_file)
BTF_ID(struct, cgroup)

/* Index of bpf_view_btf_ids */
enum {
	BTF_ID_SEQ_FILE = 0,
	BTF_ID_CGROUP,
};

static void register_bpf_view_target(struct bpf_view_target_info *target,
				     int idx[BPF_VIEW_CTX_ARG_MAX])
{
	int i;

	for (i = 0; i < target->ctx_arg_info_size; ++i)
		target->ctx_arg_info[i].btf_id = bpf_view_btf_ids[idx[i]];

	INIT_LIST_HEAD(&target->list);
	list_add(&target->list, &targets);
}

DEFINE_BPF_VIEW_FUNC(cgroup, struct seq_file *seq, struct cgroup *cgroup)

static struct bpf_view_target_info cgroup_view_tinfo = {
	.target			= "cgroup",
	.ctx_arg_info_size	= 2,
	.ctx_arg_info		= {
		{ offsetof(struct bpf_view_cgroup_ctx, seq), PTR_TO_BTF_ID },
		{ offsetof(struct bpf_view_cgroup_ctx, cgroup), PTR_TO_BTF_ID },
	},
	.btf_id			= 0,
};

static int __init bpf_view_init(void)
{
	int cgroup_view_idx[BPF_VIEW_CTX_ARG_MAX] = {
		BTF_ID_SEQ_FILE, BTF_ID_CGROUP };

	register_bpf_view_target(&cgroup_view_tinfo, cgroup_view_idx);

	return 0;
}
late_initcall(bpf_view_init);

