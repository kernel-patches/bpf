// SPDX-License-Identifier: GPL-2.0
/*
 * Author: Yafang Shao <laoar.shao@gmail.com>
 */

#include <linux/bpf.h>
#include <linux/mm_types.h>

__bpf_hook_start();

/* Checks if this @vma can use THP. */
__weak noinline int
mm_bpf_thp_vma_allowable(struct vm_area_struct *vma)
{
	/* At present, fmod_ret exclusively uses 0 to signify that the return
	 * value remains unchanged.
	 */
	return 0;
}

__bpf_hook_end();

BTF_SET8_START(mm_bpf_fmod_ret_ids)
BTF_ID_FLAGS(func, mm_bpf_thp_vma_allowable)
BTF_SET8_END(mm_bpf_fmod_ret_ids)

static const struct btf_kfunc_id_set mm_bpf_fmodret_set = {
	.owner = THIS_MODULE,
	.set   = &mm_bpf_fmod_ret_ids,
};

static int __init bpf_mm_kfunc_init(void)
{
	return register_btf_fmodret_id_set(&mm_bpf_fmodret_set);
}
late_initcall(bpf_mm_kfunc_init);
