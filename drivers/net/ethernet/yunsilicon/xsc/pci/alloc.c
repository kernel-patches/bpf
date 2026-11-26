// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021-2026, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 * Copyright (c) 2013-2016, Mellanox Technologies. All rights reserved.
 */

#include <linux/dma-mapping.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include "alloc.h"

int xsc_buf_alloc(struct xsc_core_device *xdev,
		  unsigned long size,
		  unsigned long max_direct,
		  struct xsc_buf *buf)
{
	dma_addr_t t;

	buf->size = size;
	if (size <= max_direct) {
		buf->nbufs      = 1;
		buf->npages     = 1;
		buf->page_shift = get_order(size) + PAGE_SHIFT;
		buf->direct.buf = dma_alloc_coherent(&xdev->pdev->dev, size, &t,
						     GFP_KERNEL);
		if (!buf->direct.buf)
			return -ENOMEM;

		buf->direct.map = t;

		while (t & GENMASK(buf->page_shift - 1, 0)) {
			--buf->page_shift;
			buf->npages *= 2;
		}
	} else {
		struct page **pages;
		unsigned int i;

		buf->direct.buf = NULL;
		buf->nbufs      = DIV_ROUND_UP(size, PAGE_SIZE);
		buf->npages     = buf->nbufs;
		buf->page_shift = PAGE_SHIFT;
		buf->page_list  = kcalloc(buf->nbufs, sizeof(*buf->page_list),
					  GFP_KERNEL);
		if (!buf->page_list)
			return -ENOMEM;

		for (i = 0; i < buf->nbufs; i++) {
			buf->page_list[i].buf =
				dma_alloc_coherent(&xdev->pdev->dev, PAGE_SIZE,
						   &t, GFP_KERNEL);
			if (!buf->page_list[i].buf)
				goto err_free;

			buf->page_list[i].map = t;
		}

		pages = kmalloc_array(buf->nbufs, sizeof(*pages), GFP_KERNEL);
		if (!pages)
			goto err_free;

		for (i = 0; i < buf->nbufs; i++) {
			void *addr = buf->page_list[i].buf;

			if (is_vmalloc_addr(addr))
				pages[i] = vmalloc_to_page(addr);
			else
				pages[i] = virt_to_page(addr);
		}
		buf->direct.buf = vmap(pages, buf->nbufs, VM_MAP, PAGE_KERNEL);
		kfree(pages);
		if (!buf->direct.buf)
			goto err_free;
	}

	return 0;

err_free:
	xsc_buf_free(xdev, buf);

	return -ENOMEM;
}

void xsc_buf_free(struct xsc_core_device *xdev, struct xsc_buf *buf)
{
	unsigned int i;

	if (buf->nbufs == 1) {
		dma_free_coherent(&xdev->pdev->dev, buf->size, buf->direct.buf,
				  buf->direct.map);
	} else {
		if (buf->direct.buf)
			vunmap(buf->direct.buf);

		for (i = 0; i < buf->nbufs; i++)
			if (buf->page_list[i].buf)
				dma_free_coherent(&xdev->pdev->dev, PAGE_SIZE,
						  buf->page_list[i].buf,
						  buf->page_list[i].map);
		kfree(buf->page_list);
	}
}

void xsc_fill_page_array(struct xsc_buf *buf, __be64 *pas, unsigned int npages)
{
	unsigned int shift = PAGE_SHIFT - XSC_PAGE_SHIFT_4K;
	unsigned int mask = (1 << shift) - 1;
	unsigned int i;
	u64 addr;

	for (i = 0; i < npages; i++) {
		if (buf->nbufs == 1)
			addr = buf->direct.map + (i << XSC_PAGE_SHIFT_4K);
		else
			addr = buf->page_list[i >> shift].map +
			       ((i & mask) << XSC_PAGE_SHIFT_4K);

		pas[i] = cpu_to_be64(addr);
	}
}
EXPORT_SYMBOL_GPL(xsc_fill_page_array);

void xsc_core_fill_page_frag_array(struct xsc_frag_buf *buf,
				   __be64 *pas,
				   unsigned int npages)
{
	int i;
	dma_addr_t addr;
	unsigned int shift = PAGE_SHIFT - XSC_PAGE_SHIFT_4K;
	unsigned int mask = (1 << shift) - 1;

	for (i = 0; i < npages; i++) {
		addr = buf->frags[i >> shift].map +
			((i & mask) << XSC_PAGE_SHIFT_4K);
		pas[i] = cpu_to_be64(addr);
	}
}
EXPORT_SYMBOL_GPL(xsc_core_fill_page_frag_array);

static void *xsc_dma_zalloc_coherent_node(struct xsc_core_device *xdev,
					  size_t size, dma_addr_t *dma_handle,
					  int node)
{
	struct device *device = &xdev->pdev->dev;
	int original_node;
	void *cpu_handle;

	/* WA for kernels that don't use numa_mem_id in alloc_pages_node */
	if (node == NUMA_NO_NODE)
		node = numa_mem_id();

	original_node = dev_to_node(device);
	set_dev_node(device, node);
	cpu_handle = dma_alloc_coherent(device, size, dma_handle, GFP_KERNEL);
	set_dev_node(device, original_node);

	return cpu_handle;
}

int xsc_core_frag_buf_alloc_node(struct xsc_core_device *xdev,
				 unsigned long size,
				 struct xsc_frag_buf *buf,
				 int node)
{
	int i;

	buf->size = size;
	buf->npages = DIV_ROUND_UP(size, PAGE_SIZE);
	buf->page_shift = PAGE_SHIFT;
	buf->frags = kcalloc(buf->npages, sizeof(struct xsc_buf_list),
			     GFP_KERNEL);
	if (!buf->frags)
		goto err_out;

	for (i = 0; i < buf->npages; i++) {
		unsigned long frag_sz = min_t(unsigned long, size, PAGE_SIZE);
		struct xsc_buf_list *frag = &buf->frags[i];

		frag->buf = xsc_dma_zalloc_coherent_node(xdev, frag_sz,
							 &frag->map, node);
		if (!frag->buf)
			goto err_free_buf;
		if (frag->map & ((1 << buf->page_shift) - 1)) {
			dma_free_coherent(&xdev->pdev->dev, frag_sz,
					  buf->frags[i].buf, buf->frags[i].map);
			pci_err(xdev->pdev, "unexpected map alignment: %pad, page_shift=%d\n",
				&frag->map, buf->page_shift);
			goto err_free_buf;
		}
		size -= frag_sz;
	}

	return 0;

err_free_buf:
	while (i--)
		dma_free_coherent(&xdev->pdev->dev,
				  PAGE_SIZE,
				  buf->frags[i].buf,
				  buf->frags[i].map);
	kfree(buf->frags);
err_out:
	return -ENOMEM;
}
EXPORT_SYMBOL_GPL(xsc_core_frag_buf_alloc_node);

void xsc_core_frag_buf_free(struct xsc_core_device *xdev,
			    struct xsc_frag_buf *buf)
{
	unsigned long size = buf->size;
	int i;

	for (i = 0; i < buf->npages; i++) {
		unsigned long frag_sz = min_t(unsigned long, size, PAGE_SIZE);

		dma_free_coherent(&xdev->pdev->dev, frag_sz, buf->frags[i].buf,
				  buf->frags[i].map);
		size -= frag_sz;
	}
	kfree(buf->frags);
}
EXPORT_SYMBOL_GPL(xsc_core_frag_buf_free);
