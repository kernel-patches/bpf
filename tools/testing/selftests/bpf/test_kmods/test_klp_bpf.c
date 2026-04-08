// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/livepatch.h>
#include <linux/seq_file.h>
#include <linux/bpf_verifier.h>
#include "test_klp_bpf.h"

static struct klp_bpf_cmdline_ops *active_ops;

/* --- kfunc: allow BPF struct_ops programs to write to seq_file --- */

__bpf_kfunc_start_defs();

__bpf_kfunc void bpf_klp_seq_write(struct seq_file *m,
				    const char *data, u32 data__sz)
{
	seq_write(m, data, data__sz);
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(klp_bpf_kfunc_ids)
BTF_ID_FLAGS(func, bpf_klp_seq_write)
BTF_KFUNCS_END(klp_bpf_kfunc_ids)

static const struct btf_kfunc_id_set klp_bpf_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &klp_bpf_kfunc_ids,
};

/* --- Livepatch replacement for cmdline_proc_show --- */

static int livepatch_cmdline_proc_show(struct seq_file *m, void *v)
{
	struct klp_bpf_cmdline_ops *ops = READ_ONCE(active_ops);

	if (ops && ops->set_cmdline)
		return ops->set_cmdline(m);

	seq_printf(m, "%s: no struct_ops attached\n", THIS_MODULE->name);
	return 0;
}

static struct klp_func funcs[] = {
	{
		.old_name = "cmdline_proc_show",
		.new_func = livepatch_cmdline_proc_show,
	}, { }
};

static struct klp_object objs[] = {
	{
		/* name being NULL means vmlinux */
		.funcs = funcs,
	}, { }
};

static struct klp_patch patch = {
	.mod = THIS_MODULE,
	.objs = objs,
};

/* --- struct_ops registration --- */

static int klp_bpf_cmdline_reg(void *kdata, struct bpf_link *link)
{
	struct klp_bpf_cmdline_ops *ops = kdata;

	if (cmpxchg(&active_ops, NULL, ops))
		return -EBUSY;

	return 0;
}

static void klp_bpf_cmdline_unreg(void *kdata, struct bpf_link *link)
{
	WRITE_ONCE(active_ops, NULL);
}

static int klp_bpf_cmdline_init(struct btf *btf)
{
	return 0;
}

static int klp_bpf_cmdline_init_member(const struct btf_type *t,
				       const struct btf_member *member,
				       void *kdata, const void *udata)
{
	return 0;
}

static bool klp_bpf_cmdline_is_valid_access(int off, int size,
					    enum bpf_access_type type,
					    const struct bpf_prog *prog,
					    struct bpf_insn_access_aux *info)
{
	return bpf_tracing_btf_ctx_access(off, size, type, prog, info);
}

static int klp_bpf_cmdline_btf_struct_access(struct bpf_verifier_log *log,
					     const struct bpf_reg_state *reg,
					     int off, int size)
{
	return -EACCES;
}

static const struct bpf_verifier_ops klp_bpf_cmdline_verifier_ops = {
	.is_valid_access = klp_bpf_cmdline_is_valid_access,
	.btf_struct_access = klp_bpf_cmdline_btf_struct_access,
};

/* CFI stubs */
static int klp_bpf_cmdline__set_cmdline(struct seq_file *m)
{
	return 0;
}

static struct klp_bpf_cmdline_ops __bpf_klp_bpf_cmdline_ops = {
	.set_cmdline = klp_bpf_cmdline__set_cmdline,
};

static struct bpf_struct_ops bpf_klp_bpf_cmdline_ops = {
	.verifier_ops = &klp_bpf_cmdline_verifier_ops,
	.init = klp_bpf_cmdline_init,
	.init_member = klp_bpf_cmdline_init_member,
	.reg = klp_bpf_cmdline_reg,
	.unreg = klp_bpf_cmdline_unreg,
	.cfi_stubs = &__bpf_klp_bpf_cmdline_ops,
	.name = "klp_bpf_cmdline_ops",
	.owner = THIS_MODULE,
};

/* --- Module init/exit --- */

static int __init test_klp_bpf_init(void)
{
	int ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					&klp_bpf_kfunc_set);
	ret = ret ?: register_bpf_struct_ops(&bpf_klp_bpf_cmdline_ops,
					     klp_bpf_cmdline_ops);
	if (ret)
		return ret;

	return klp_enable_patch(&patch);
}

static void __exit test_klp_bpf_exit(void)
{
}

module_init(test_klp_bpf_init);
module_exit(test_klp_bpf_exit);
MODULE_LICENSE("GPL");
MODULE_INFO(livepatch, "Y");
MODULE_AUTHOR("Song Liu");
MODULE_DESCRIPTION("Test: BPF struct_ops + livepatch integration");
