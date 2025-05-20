// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/huge_mm.h>

struct bpf_thp_ops {
	/**
	 * @thp_bpf_allowable: Determines whether a task is permitted to
	 * allocate a THP when it is allocating anon memory.
	 *
	 * Return: %true if THP allocation is allowed, %false otherwise.
	 */
	bool (*thp_bpf_allowable)(void);
};

static struct bpf_thp_ops bpf_thp;

bool hugepage_bpf_allowable(void)
{
	/* Works only for "bpf" mode */
	if (!(transparent_hugepage_flags & (1<<TRANSPARENT_HUGEPAGE_REQ_BPF_FLAG)))
		return 0;

	/* No BPF program is attached */
	if (!(transparent_hugepage_flags & (1<<TRANSPARENT_HUGEPAGE_BPF_ATTACHED)))
		return 0;

	/* BPF adjustment hook */
	if (bpf_thp.thp_bpf_allowable)
		return bpf_thp.thp_bpf_allowable();
	return 0;
}

static bool bpf_thp_ops_is_valid_access(int off, int size,
					enum bpf_access_type type,
					const struct bpf_prog *prog,
					struct bpf_insn_access_aux *info)
{
	return bpf_tracing_btf_ctx_access(off, size, type, prog, info);
}

static const struct bpf_func_proto *
bpf_thp_get_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	return bpf_base_func_proto(func_id, prog);
}

static const struct bpf_verifier_ops thp_bpf_verifier_ops = {
	.get_func_proto = bpf_thp_get_func_proto,
	.is_valid_access = bpf_thp_ops_is_valid_access,
};

static int bpf_thp_reg(void *kdata, struct bpf_link *link)
{
	struct bpf_thp_ops *ops = kdata;

	/* TODO: add support for multiple attaches */
	if (test_and_set_bit(TRANSPARENT_HUGEPAGE_BPF_ATTACHED,
		&transparent_hugepage_flags))
		return -EOPNOTSUPP;
	bpf_thp.thp_bpf_allowable = ops->thp_bpf_allowable;
	return 0;
}

static void bpf_thp_unreg(void *kdata, struct bpf_link *link)
{
	clear_bit(TRANSPARENT_HUGEPAGE_BPF_ATTACHED, &transparent_hugepage_flags);
	bpf_thp.thp_bpf_allowable = NULL;
}

static int bpf_thp_check_member(const struct btf_type *t,
				const struct btf_member *member,
				const struct bpf_prog *prog)
{
	return 0;
}

static int bpf_thp_init_member(const struct btf_type *t,
			       const struct btf_member *member,
			       void *kdata, const void *udata)
{
	return 0;
}

static int bpf_thp_init(struct btf *btf)
{
	return 0;
}

static bool thp_bpf_allowable(void)
{
	return 0;
}

static struct bpf_thp_ops __bpf_thp_ops = {
	.thp_bpf_allowable = thp_bpf_allowable,
};

static struct bpf_struct_ops bpf_bpf_thp_ops = {
	.verifier_ops = &thp_bpf_verifier_ops,
	.init = bpf_thp_init,
	.check_member = bpf_thp_check_member,
	.init_member = bpf_thp_init_member,
	.reg = bpf_thp_reg,
	.unreg = bpf_thp_unreg,
	.name = "bpf_thp_ops",
	.cfi_stubs = &__bpf_thp_ops,
	.owner = THIS_MODULE,
};

static int __init bpf_thp_ops_init(void)
{
	int err = register_bpf_struct_ops(&bpf_bpf_thp_ops, bpf_thp_ops);

	if (err)
		pr_err("bpf_thp: Failed to register struct_ops (%d)\n", err);
	return err;
}
late_initcall(bpf_thp_ops_init);
