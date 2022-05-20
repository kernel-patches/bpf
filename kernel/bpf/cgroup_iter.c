// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2022 Google */
#include <linux/bpf.h>
#include <linux/btf_ids.h>
#include <linux/cgroup.h>
#include <linux/kernel.h>
#include <linux/seq_file.h>

struct bpf_iter__cgroup {
	__bpf_md_ptr(struct bpf_iter_meta *, meta);
	__bpf_md_ptr(struct cgroup *, cgroup);
};

static void *cgroup_iter_seq_start(struct seq_file *seq, loff_t *pos)
{
	/* Only one session is supported. */
	if (*pos > 0)
		return NULL;

	if (*pos == 0)
		++*pos;

	return *(struct cgroup **)seq->private;
}

static void *cgroup_iter_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	++*pos;
	return NULL;
}

static int cgroup_iter_seq_show(struct seq_file *seq, void *v)
{
	struct bpf_iter__cgroup ctx;
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

static void cgroup_iter_seq_stop(struct seq_file *seq, void *v)
{
}

static const struct seq_operations cgroup_iter_seq_ops = {
	.start  = cgroup_iter_seq_start,
	.next   = cgroup_iter_seq_next,
	.stop   = cgroup_iter_seq_stop,
	.show   = cgroup_iter_seq_show,
};

BTF_ID_LIST_SINGLE(bpf_cgroup_btf_id, struct, cgroup)

static int cgroup_iter_seq_init(void *priv_data, struct bpf_iter_aux_info *aux)
{
	*(struct cgroup **)priv_data = aux->cgroup;
	return 0;
}

static const struct bpf_iter_seq_info cgroup_iter_seq_info = {
	.seq_ops                = &cgroup_iter_seq_ops,
	.init_seq_private       = cgroup_iter_seq_init,
	.seq_priv_size          = sizeof(struct cgroup *),
};

static int bpf_iter_attach_cgroup(struct bpf_prog *prog,
				  union bpf_iter_link_info *linfo,
				  struct bpf_iter_aux_info *aux)
{
	struct cgroup *cgroup;

	cgroup = cgroup_get_from_id(linfo->cgroup.cgroup_id);
	if (!cgroup)
		return -EBUSY;

	aux->cgroup = cgroup;
	return 0;
}

static void bpf_iter_detach_cgroup(struct bpf_iter_aux_info *aux)
{
	if (aux->cgroup)
		cgroup_put(aux->cgroup);
}

static void bpf_iter_cgroup_show_fdinfo(const struct bpf_iter_aux_info *aux,
					struct seq_file *seq)
{
	char *buf;

	seq_printf(seq, "cgroup_id:\t%llu\n", cgroup_id(aux->cgroup));

	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf) {
		seq_puts(seq, "cgroup_path:\n");
		return;
	}

	/* If cgroup_path_ns() fails, buf will be an empty string, cgroup_path
	 * will print nothing.
	 *
	 * Cgroup_path is the path in the calliing process's cgroup namespace.
	 */
	cgroup_path_ns(aux->cgroup, buf, sizeof(buf),
		       current->nsproxy->cgroup_ns);
	seq_printf(seq, "cgroup_path:\t%s\n", buf);
	kfree(buf);
}

static int bpf_iter_cgroup_fill_link_info(const struct bpf_iter_aux_info *aux,
					  struct bpf_link_info *info)
{
	info->iter.cgroup.cgroup_id = cgroup_id(aux->cgroup);
	return 0;
}

DEFINE_BPF_ITER_FUNC(cgroup, struct bpf_iter_meta *meta,
		     struct cgroup *cgroup)

static struct bpf_iter_reg bpf_cgroup_reg_info = {
	.target			= "cgroup",
	.attach_target		= bpf_iter_attach_cgroup,
	.detach_target		= bpf_iter_detach_cgroup,
	.show_fdinfo		= bpf_iter_cgroup_show_fdinfo,
	.fill_link_info		= bpf_iter_cgroup_fill_link_info,
	.ctx_arg_info_size	= 1,
	.ctx_arg_info		= {
		{ offsetof(struct bpf_iter__cgroup, cgroup),
		  PTR_TO_BTF_ID },
	},
	.seq_info		= &cgroup_iter_seq_info,
};

static int __init bpf_cgroup_iter_init(void)
{
	bpf_cgroup_reg_info.ctx_arg_info[0].btf_id = bpf_cgroup_btf_id[0];
	return bpf_iter_reg_target(&bpf_cgroup_reg_info);
}

late_initcall(bpf_cgroup_iter_init);
