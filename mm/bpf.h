/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __MM_BPF_H
#define __MM_BPF_H

#define MM_BPF_ALLOWABLE	(1)
#define MM_BPF_NOT_ALLOWABLE	(-1)

#define MM_BPF_ALLOWABLE_HOOK(func, args...)	{	\
	int ret = func(args);				\
							\
	if (ret == MM_BPF_ALLOWABLE)			\
		return 1;				\
	if (ret == MM_BPF_NOT_ALLOWABLE)		\
		return 0;				\
}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
int mm_bpf_thp_vma_allowable(struct vm_area_struct *vma);
#endif

#endif
