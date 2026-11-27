// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020-2025 Intel Corporation
 */

#include <linux/dma-buf.h>
#include <linux/err.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/capability.h>

#include <drm/drm_device.h>
#include <drm/drm_file.h>
#include <drm/drm_gem.h>

#include "ivpu_drv.h"
#include "ivpu_gem.h"

struct ivpu_userptr {
	struct page **pages;
	unsigned long nr_pages;
};

static struct sg_table *
ivpu_gem_userptr_dmabuf_map(struct dma_buf_attachment *attachment,
			    enum dma_data_direction direction)
{
	struct ivpu_userptr *userptr = attachment->dmabuf->priv;
	struct sg_table *sgt;
	int ret;

	sgt = kmalloc_obj(*sgt);
	if (!sgt)
		return ERR_PTR(-ENOMEM);

	ret = sg_alloc_table_from_pages(sgt, userptr->pages, userptr->nr_pages, 0,
					attachment->dmabuf->size, GFP_KERNEL);
	if (ret)
		goto free_sgt;

	ret = dma_map_sgtable(attachment->dev, sgt, direction, DMA_ATTR_SKIP_CPU_SYNC);
	if (ret)
		goto free_table;

	return sgt;

free_table:
	sg_free_table(sgt);
free_sgt:
	kfree(sgt);
	return ERR_PTR(ret);
}

static void ivpu_gem_userptr_dmabuf_unmap(struct dma_buf_attachment *attachment,
					  struct sg_table *sgt,
					  enum dma_data_direction direction)
{
	dma_unmap_sgtable(attachment->dev, sgt, direction, DMA_ATTR_SKIP_CPU_SYNC);
	sg_free_table(sgt);
	kfree(sgt);
}

static void ivpu_gem_userptr_dmabuf_release(struct dma_buf *dma_buf)
{
	struct ivpu_userptr *userptr = dma_buf->priv;

	unpin_user_pages(userptr->pages, userptr->nr_pages);
	kvfree(userptr->pages);
	kfree(userptr);
}

static const struct dma_buf_ops ivpu_gem_userptr_dmabuf_ops = {
	.map_dma_buf = ivpu_gem_userptr_dmabuf_map,
	.unmap_dma_buf = ivpu_gem_userptr_dmabuf_unmap,
	.release = ivpu_gem_userptr_dmabuf_release,
};

static struct dma_buf *
ivpu_create_userptr_dmabuf(struct ivpu_device *vdev, void __user *user_ptr,
			   size_t size, uint32_t flags)
{
	struct dma_buf_export_info exp_info = {};
	struct dma_buf *dma_buf;
	struct ivpu_userptr *userptr;
	struct page **pages;
	unsigned long nr_pages = size >> PAGE_SHIFT;
	unsigned int gup_flags = FOLL_LONGTERM;
	int ret, i, pinned;

	/* Add FOLL_WRITE only if the BO is not read-only */
	if (!(flags & DRM_IVPU_BO_READ_ONLY))
		gup_flags |= FOLL_WRITE;

	pages = kvmalloc_objs(*pages, nr_pages);
	if (!pages)
		return ERR_PTR(-ENOMEM);

	pinned = pin_user_pages_fast((unsigned long)user_ptr, nr_pages, gup_flags, pages);
	if (pinned < 0) {
		ret = pinned;
		ivpu_dbg(vdev, IOCTL, "Failed to pin user pages: %d\n", ret);
		goto free_pages_array;
	}

	if (pinned != nr_pages) {
		ivpu_dbg(vdev, IOCTL, "Pinned %d pages, expected %lu\n", pinned, nr_pages);
		ret = -EFAULT;
		goto unpin_pages;
	}

	userptr = kmalloc_obj(*userptr);
	if (!userptr) {
		ret = -ENOMEM;
		goto unpin_pages;
	}

	userptr->pages = pages;
	userptr->nr_pages = nr_pages;

	exp_info.exp_name = "ivpu_userptr_dmabuf";
	exp_info.owner = THIS_MODULE;
	exp_info.ops = &ivpu_gem_userptr_dmabuf_ops;
	exp_info.size = size;
	exp_info.flags = O_RDWR | O_CLOEXEC;
	exp_info.priv = userptr;

	dma_buf = dma_buf_export(&exp_info);
	if (IS_ERR(dma_buf)) {
		ret = PTR_ERR(dma_buf);
		ivpu_dbg(vdev, IOCTL, "Failed to export userptr dma-buf: %d\n", ret);
		goto free_userptr;
	}

	return dma_buf;

free_userptr:
	kfree(userptr);
unpin_pages:
	for (i = 0; i < pinned; i++)
		unpin_user_page(pages[i]);
free_pages_array:
	kvfree(pages);
	return ERR_PTR(ret);
}

static struct ivpu_bo *
ivpu_bo_create_from_userptr(struct ivpu_device *vdev, void __user *user_ptr,
			    size_t size, uint32_t flags)
{
	struct dma_buf *dma_buf;
	struct drm_gem_object *obj;
	struct ivpu_bo *bo;

	dma_buf = ivpu_create_userptr_dmabuf(vdev, user_ptr, size, flags);
	if (IS_ERR(dma_buf))
		return ERR_CAST(dma_buf);

	obj = ivpu_gem_prime_import(&vdev->drm, dma_buf);
	if (IS_ERR(obj)) {
		dma_buf_put(dma_buf);
		return ERR_CAST(obj);
	}

	dma_buf_put(dma_buf);

	bo = to_ivpu_bo(obj);
	bo->flags = flags;

	return bo;
}

int ivpu_bo_create_from_userptr_ioctl(struct drm_device *dev, void *data, struct drm_file *file)
{
	struct drm_ivpu_bo_create_from_userptr *args = data;
	struct ivpu_file_priv *file_priv = file->driver_priv;
	struct ivpu_device *vdev = to_ivpu_device(dev);
	void __user *user_ptr = u64_to_user_ptr(args->user_ptr);
	struct ivpu_bo *bo;
	int ret;

	if (args->flags & ~(DRM_IVPU_BO_HIGH_MEM | DRM_IVPU_BO_DMA_MEM | DRM_IVPU_BO_READ_ONLY)) {
		ivpu_dbg(vdev, IOCTL, "Invalid BO flags: 0x%x\n", args->flags);
		return -EINVAL;
	}

	if (!args->user_ptr || !args->size) {
		ivpu_dbg(vdev, IOCTL, "Userptr or size are zero: ptr %llx size %llu\n",
			 args->user_ptr, args->size);
		return -EINVAL;
	}

	if (!PAGE_ALIGNED(args->user_ptr) || !PAGE_ALIGNED(args->size)) {
		ivpu_dbg(vdev, IOCTL, "Userptr or size not page aligned: ptr %llx size %llu\n",
			 args->user_ptr, args->size);
		return -EINVAL;
	}

	if (!access_ok(user_ptr, args->size)) {
		ivpu_dbg(vdev, IOCTL, "Userptr is not accessible: ptr %llx size %llu\n",
			 args->user_ptr, args->size);
		return -EFAULT;
	}

	bo = ivpu_bo_create_from_userptr(vdev, user_ptr, args->size, args->flags);
	if (IS_ERR(bo))
		return PTR_ERR(bo);

	ret = drm_gem_handle_create(file, &bo->base.base, &args->handle);
	if (ret) {
		ivpu_dbg(vdev, IOCTL, "Failed to create handle for BO: %pe ctx %u size %llu flags 0x%x\n",
			 bo, file_priv->ctx.id, args->size, args->flags);
	} else {
		ivpu_dbg(vdev, BO, "Created userptr BO: handle=%u vpu_addr=0x%llx size=%llu flags=0x%x\n",
			 args->handle, bo->vpu_addr, args->size, bo->flags);
		args->vpu_addr = bo->vpu_addr;
	}

	drm_gem_object_put(&bo->base.base);

	return ret;
}
