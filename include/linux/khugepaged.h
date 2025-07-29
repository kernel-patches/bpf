/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_KHUGEPAGED_H
#define _LINUX_KHUGEPAGED_H

#include <linux/huge_mm.h>

extern unsigned int khugepaged_max_ptes_none __read_mostly;
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
extern struct attribute_group khugepaged_attr_group;

extern int khugepaged_init(void);
extern void khugepaged_destroy(void);
extern int start_stop_khugepaged(void);
extern void __khugepaged_enter(struct mm_struct *mm);
extern void __khugepaged_exit(struct mm_struct *mm);
extern void khugepaged_enter_vma(struct vm_area_struct *vma,
				 unsigned long vm_flags);
extern void khugepaged_min_free_kbytes_update(void);
extern bool current_is_khugepaged(void);
extern int collapse_pte_mapped_thp(struct mm_struct *mm, unsigned long addr,
				   bool install_pmd);

static inline void khugepaged_fork(struct mm_struct *mm, struct mm_struct *oldmm)
{
	/*
	 * THP allocation policy can be dynamically modified via BPF. If a
	 * long-lived task was previously allowed to allocate THP but is no
	 * longer permitted under the new policy, we must ensure its forked
	 * child processes also inherit this restriction.
	 * The MMF_VM_HUGEPAGE flag will be cleared by khugepaged.
	 */
	if (test_bit(MMF_VM_HUGEPAGE, &oldmm->flags) &&
	    get_suggested_order(mm, 0, PMD_ORDER) == PMD_ORDER)
		__khugepaged_enter(mm);
}

static inline void khugepaged_exit(struct mm_struct *mm)
{
	if (test_bit(MMF_VM_HUGEPAGE, &mm->flags))
		__khugepaged_exit(mm);
}
#else /* CONFIG_TRANSPARENT_HUGEPAGE */
static inline void khugepaged_fork(struct mm_struct *mm, struct mm_struct *oldmm)
{
}
static inline void khugepaged_exit(struct mm_struct *mm)
{
}
static inline void khugepaged_enter_vma(struct vm_area_struct *vma,
					unsigned long vm_flags)
{
}
static inline int collapse_pte_mapped_thp(struct mm_struct *mm,
					  unsigned long addr, bool install_pmd)
{
	return 0;
}

static inline void khugepaged_min_free_kbytes_update(void)
{
}

static inline bool current_is_khugepaged(void)
{
	return false;
}
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */

#endif /* _LINUX_KHUGEPAGED_H */
