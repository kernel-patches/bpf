// SPDX-License-Identifier: GPL-2.0
#include <linux/mm.h>
#include <linux/page_ext.h>
#include <linux/active_vm.h>
#include <linux/slab.h>

#include "active_vm.h"
#include "slab.h"

static bool __active_vm_enabled __initdata =
				IS_ENABLED(CONFIG_ACTIVE_VM);

DEFINE_STATIC_KEY_TRUE(active_vm_disabled);
EXPORT_SYMBOL(active_vm_disabled);

static int __init early_active_vm_param(char *buf)
{
	return strtobool(buf, &__active_vm_enabled);
}

early_param("active_vm", early_active_vm_param);

static bool __init need_active_vm(void)
{
	return __active_vm_enabled;
}

static void __init init_active_vm(void)
{
	if (!__active_vm_enabled)
		return;

	static_branch_disable(&active_vm_disabled);
}

struct active_vm {
	union {
		int *slab_data;     /* for slab */
		unsigned long page_data;	/* for page */
	}
};

struct page_ext_operations active_vm_ops = {
	.size = sizeof(struct active_vm),
	.need = need_active_vm,
	.init = init_active_vm,
};

DEFINE_PER_CPU(int, irq_active_vm_item);
DEFINE_PER_CPU(int, soft_active_vm_item);
EXPORT_PER_CPU_SYMBOL(irq_active_vm_item);
EXPORT_PER_CPU_SYMBOL(soft_active_vm_item);
DEFINE_PER_CPU(struct active_vm_stat, active_vm_stats);
EXPORT_PER_CPU_SYMBOL(active_vm_stats);

long active_vm_item_sum(int item)
{
	struct active_vm_stat *this;
	long sum = 0;
	int cpu;

	WARN_ON_ONCE(item <= 0);
	for_each_online_cpu(cpu) {
		this = &per_cpu(active_vm_stats, cpu);
		sum += this->stat[item - 1];
	}

	return sum;
}

static int *active_vm_from_slab(struct page_ext *page_ext)
{
	struct active_vm *av;

	if (static_branch_likely(&active_vm_disabled))
		return NULL;

	av = (void *)(page_ext) + active_vm_ops.offset;
	return READ_ONCE(av->slab_data);
}

void active_vm_slab_free(struct slab *slab)
{
	struct page_ext *page_ext;
	struct active_vm *av;
	struct page *page;

	page = slab_page(slab);
	page_ext = page_ext_get(page);
	if (!page_ext)
		return;

	av = (void *)(page_ext) + active_vm_ops.offset;
	kfree(av->slab_data);
	av->slab_data = NULL;
	page_ext_put(page_ext);
}

static bool active_vm_slab_cmpxchg(struct page_ext *page_ext, int *new)
{
	struct active_vm *av;

	av = (void *)(page_ext) + active_vm_ops.offset;
	return cmpxchg(&av->slab_data, NULL, new) == NULL;
}

void active_vm_slab_add(struct kmem_cache *s, gfp_t flags, size_t size, void **p)
{
	struct page_ext *page_ext;
	struct slab *slab;
	struct page *page;
	int *vec;
	int item;
	int off;
	int i;

	item = active_vm_item();
	for (i = 0; i < size; i++) {
		slab = virt_to_slab(p[i]);
		page = slab_page(slab);
		page_ext = page_ext_get(page);

		if (!page_ext)
			continue;

		off = obj_to_index(s, slab, p[i]);
		vec = active_vm_from_slab(page_ext);
		if (!vec) {
			vec = kcalloc_node(objs_per_slab(s, slab), sizeof(int),
						flags & ~__GFP_ACCOUNT, slab_nid(slab));
			if (!vec) {
				page_ext_put(page_ext);
				continue;
			}

			if (!active_vm_slab_cmpxchg(page_ext, vec)) {
				kfree(vec);
				vec = active_vm_from_slab(page_ext);
			}
		}

		vec[off] = item;
		active_vm_item_add(item, obj_full_size(s));
		page_ext_put(page_ext);
	}
}

void active_vm_slab_sub(struct kmem_cache *s, struct slab *slab, void **p, int cnt)
{
	struct page *page = slab_page(slab);
	struct page_ext *page_ext = page_ext_get(page);
	int *vec;
	int off;
	int i;

	if (!page_ext)
		return;

	for (i = 0; i < cnt; i++) {
		vec = active_vm_from_slab(page_ext);
		if (vec) {
			off = obj_to_index(s, slab, p[i]);
			if (vec[off] > 0) {
				active_vm_item_sub(vec[off], obj_full_size(s));
				vec[off] = 0;
			}
		}
	}
	page_ext_put(page_ext);
}

void page_set_active_vm(struct page *page, unsigned int item, unsigned int order)
{
	struct page_ext *page_ext = page_ext_get(page);
	struct active_vm *av;

	if (unlikely(!page_ext))
		return;

	av = (void *)(page_ext) + active_vm_ops.offset;
	WARN_ON_ONCE(av->page_data != 0);
	av->page_data = item;
	page_ext_put(page_ext);
	active_vm_item_add(item, PAGE_SIZE << order);
}

void page_test_clear_active_vm(struct page *page, unsigned int order)
{
	struct page_ext *page_ext = page_ext_get(page);
	struct active_vm *av;

	if (unlikely(!page_ext))
		return;

	av = (void *)(page_ext) + active_vm_ops.offset;
	if (av->page_data <= 0)
		goto out;

	active_vm_item_sub(av->page_data, PAGE_SIZE << order);
	av->page_data = 0;
out:
	page_ext_put(page_ext);
}
