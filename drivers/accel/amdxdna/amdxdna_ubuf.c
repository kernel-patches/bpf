// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include <drm/amdxdna_accel.h>
#include <drm/drm_device.h>
#include <drm/drm_print.h>
#include <linux/overflow.h>
#include <linux/pagemap.h>
#include <linux/vmalloc.h>

#include "amdxdna_gem.h"
#include "amdxdna_pci_drv.h"
#include "amdxdna_ubuf.h"

static int amdxdna_ubuf_hmm_register(struct amdxdna_client *client,
				     struct amdxdna_gem_obj *abo,
				     struct amdxdna_drm_va_entry *va_ent)
{
	struct vm_area_struct *vma;
	int ret;

	mmap_write_lock(client->mm);
	vma = find_vma(client->mm, va_ent->vaddr);
	if (!vma || vma->vm_start > va_ent->vaddr ||
	    vma->vm_end - va_ent->vaddr < va_ent->len) {
		ret = -EINVAL;
		goto unlock;
	}

	ret = amdxdna_hmm_register(abo, vma, va_ent->vaddr - vma->vm_start, va_ent->len);
	if (!ret && !(vma->vm_flags & (VM_PFNMAP | VM_IO)))
		amdxdna_mark_map_invalid(abo);

unlock:
	mmap_write_unlock(client->mm);

	return ret;
}

static void amdxdna_gem_ubuf_obj_free(struct drm_gem_object *gobj)
{
	struct amdxdna_gem_obj *abo = to_xdna_obj(gobj);

	amdxdna_hmm_unreg_umaps(abo, true);
	cancel_work_sync(&abo->hmm_unreg_work);

	drm_gem_object_release(gobj);
	amdxdna_gem_destroy_obj(abo);
}

static struct dma_buf *amdxdna_gem_ubuf_obj_export(struct drm_gem_object *gobj, int flags)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static const struct drm_gem_object_funcs amdxdna_gem_ubuf_obj_funcs = {
	.free = amdxdna_gem_ubuf_obj_free,
	.open = amdxdna_gem_obj_open,
	.close = amdxdna_gem_obj_close,
	.export = amdxdna_gem_ubuf_obj_export,
};

struct amdxdna_gem_obj *amdxdna_alloc_ubuf_bo(struct amdxdna_client *client,
					      u32 num_entries, void __user *va_entries)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_drm_va_entry *va_ent;
	struct amdxdna_gem_obj *abo;
	size_t bufsize;
	long ret;

	if (!amdxdna_pasid_on(client))
		return ERR_PTR(-EOPNOTSUPP);

	/*
	 * There is not any valid case to use more than 1 entry.
	 * Hardcode maximum entries to 1.
	 */
	if (num_entries > 1)
		return ERR_PTR(-EINVAL);

	if (current->mm != client->mm)
		return ERR_PTR(-EINVAL);

	va_ent = kvzalloc_obj(*va_ent);
	if (!va_ent)
		return ERR_PTR(-ENOMEM);

	if (copy_from_user(va_ent, va_entries, sizeof(*va_ent))) {
		XDNA_DBG(xdna, "Access va entries failed");
		ret = -EINVAL;
		goto free_ent;
	}

	if (!IS_ALIGNED(va_ent->vaddr, PAGE_SIZE) ||
	    !IS_ALIGNED(va_ent->len, PAGE_SIZE) ||
	    !va_ent->len ||
	    check_add_overflow(va_ent->vaddr, va_ent->len, &bufsize)) {
		XDNA_DBG(xdna, "Invalid address or len %llx, %llx",
			 va_ent->vaddr, va_ent->len);
		ret = -EINVAL;
		goto free_ent;
	}

	bufsize = va_ent->len;
	abo = amdxdna_gem_create_obj(&xdna->ddev, bufsize);
	if (IS_ERR(abo)) {
		ret = PTR_ERR(abo);
		goto free_ent;
	}

	abo->type = AMDXDNA_BO_SHARE;
	abo->mem.uva = va_ent->vaddr;
	to_gobj(abo)->funcs = &amdxdna_gem_ubuf_obj_funcs;
	drm_gem_private_object_init(&xdna->ddev, to_gobj(abo), bufsize);

	ret = amdxdna_ubuf_hmm_register(client, abo, va_ent);
	if (ret)
		goto put_obj;

	kvfree(va_ent);

	return abo;

put_obj:
	drm_gem_object_put(to_gobj(abo));
free_ent:
	kvfree(va_ent);
	return ERR_PTR(ret);
}
