/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __MM_ACTIVE_VM_H
#define __MM_ACTIVE_VM_H

#ifdef CONFIG_ACTIVE_VM
#include <linux/active_vm.h>
#include <linux/page_ext.h>

extern struct page_ext_operations active_vm_ops;
void active_vm_slab_add(struct kmem_cache *s, gfp_t flags, size_t size, void **p);
void active_vm_slab_sub(struct kmem_cache *s, struct slab *slab, void **p, int cnt);
void active_vm_slab_free(struct slab *slab);
void page_set_active_vm(struct page *page, unsigned int item, unsigned int order);
void page_test_clear_active_vm(struct page *page, unsigned int order);

static inline int active_vm_item(void)
{
	if (in_irq())
		return this_cpu_read(irq_active_vm_item);

	if (in_softirq())
		return this_cpu_read(soft_active_vm_item);

	return current->active_vm_item;
}

static inline void active_vm_item_add(int item, long delta)
{
	WARN_ON_ONCE(item <= 0);
	this_cpu_add(active_vm_stats.stat[item - 1], delta);
}

static inline void active_vm_item_sub(int item, long delta)
{
	WARN_ON_ONCE(item <= 0);
	this_cpu_sub(active_vm_stats.stat[item - 1], delta);
}

#else /* CONFIG_ACTIVE_VM */
static inline int active_vm_item(void)
{
	return 0;
}

static inline void active_vm_item_add(int item, long delta)
{
}

static inline void active_vm_item_sub(int item, long delta)
{
}

static inline void active_vm_slab_add(struct kmem_cache *s, gfp_t flags, size_t size, void **p)
{
}

static inline void active_vm_slab_sub(struct kmem_cache *s, struct slab *slab, void **p, int cnt)
{
}

static inline void active_vm_slab_free(struct slab *slab)
{
}

static inline void page_set_active_vm(struct page *page, int item,
									  unsigned int order)
{
}

static inline void page_test_clear_active_vm(struct page *page, unsigned int order)
{
}
#endif /* CONFIG_ACTIVE_VM */
#endif /* __MM_ACTIVE_VM_H */
