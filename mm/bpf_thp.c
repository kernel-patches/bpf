// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/huge_mm.h>
#include <linux/khugepaged.h>

#define RECLAIMER_CURRENT (1 << 1)
#define RECLAIMER_KSWAPD (1 << 2)
#define RECLAIMER_BOTH (RECLAIMER_CURRENT | RECLAIMER_KSWAPD)

struct bpf_thp_ops {
	/**
	 * @allocator: Specifies whether the THP allocation is performed
	 * by the current task or by khugepaged.
	 * @vm_flags: Flags for the VMA in the current allocation context
	 * @tva_flags: Flags for the TVA in the current allocation context
	 *
	 * Rerurn:
	 * - THP_ALLOC_CURRENT: THP was allocated synchronously by the calling
	 *   task's context.
	 * - THP_ALLOC_KHUGEPAGED: THP was allocated asynchronously by the
	 *   khugepaged kernel thread.
	 * - 0: THP allocation is disallowed in the current context.
	 */
	int (*allocator)(unsigned long vm_flags, unsigned long tva_flags);
	/**
	 * @reclaimer: Specifies the entity performing page reclaim:
	 *             - current task context
	 *             - kswapd
	 *             - none (no reclaim)
	 * @vma_madvised: MADV flags for this VMA (e.g., MADV_HUGEPAGE, MADV_NOHUGEPAGE)
	 *
	 * Return:
	 * - RECLAIMER_CURRENT: Direct reclaim by the current task if THP
	 *   allocation fails.
	 * - RECLAIMER_KSWAPD: Wake kswapd to reclaim memory if THP allocation fails.
	 * - RECLAIMER_ALL: Both current and kswapd will perform the reclaim
	 * - 0: No reclaim will be attempted.
	 */
	int (*reclaimer)(bool vma_madvised);
};

static struct bpf_thp_ops bpf_thp;

int bpf_thp_allocator(unsigned long vm_flags, unsigned long tva_flags)
{
	int allocator;

	/* No BPF program is attached */
	if (!(transparent_hugepage_flags & (1<<TRANSPARENT_HUGEPAGE_BPF_ATTACHED)))
		return THP_ALLOC_KHUGEPAGED | THP_ALLOC_CURRENT;

	if (current_is_khugepaged())
		return THP_ALLOC_KHUGEPAGED | THP_ALLOC_CURRENT;
	if (!bpf_thp.allocator)
		return THP_ALLOC_KHUGEPAGED | THP_ALLOC_CURRENT;

	allocator = bpf_thp.allocator(vm_flags, tva_flags);
	if (!allocator)
		return 0;
	/* invalid return value */
	if (allocator & ~(THP_ALLOC_KHUGEPAGED | THP_ALLOC_CURRENT))
		return THP_ALLOC_KHUGEPAGED | THP_ALLOC_CURRENT;
	return allocator;
}

gfp_t bpf_thp_gfp_mask(bool vma_madvised)
{
	int reclaimer;

	if (!(transparent_hugepage_flags & (1<<TRANSPARENT_HUGEPAGE_BPF_ATTACHED)))
		return 0;

	if (!bpf_thp.reclaimer)
		return 0;

	reclaimer = bpf_thp.reclaimer(vma_madvised);
	switch (reclaimer) {
	case RECLAIMER_CURRENT:
		return GFP_TRANSHUGE | __GFP_NORETRY;
	case RECLAIMER_KSWAPD:
		return GFP_TRANSHUGE_LIGHT | __GFP_KSWAPD_RECLAIM;
	case RECLAIMER_BOTH:
		return GFP_TRANSHUGE | __GFP_KSWAPD_RECLAIM | __GFP_NORETRY;
	default:
		return 0;
	}
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
	bpf_thp.allocator = ops->allocator;
	bpf_thp.reclaimer = ops->reclaimer;
	return 0;
}

static void bpf_thp_unreg(void *kdata, struct bpf_link *link)
{
	clear_bit(TRANSPARENT_HUGEPAGE_BPF_ATTACHED, &transparent_hugepage_flags);
	bpf_thp.allocator = NULL;
	bpf_thp.reclaimer = NULL;
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

static int allocator(unsigned long vm_flags, unsigned long tva_flags)
{
	return 0;
}

static int reclaimer(bool vma_madvised)
{
	return 0;
}

static struct bpf_thp_ops __bpf_thp_ops = {
	.allocator = allocator,
	.reclaimer = reclaimer,
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
