// SPDX-License-Identifier: GPL-2.0
/*
 * VideoCore Shared Memory driver using CMA.
 *
 * Copyright: 2018, Raspberry Pi (Trading) Ltd
 * Dave Stevenson <dave.stevenson@raspberrypi.com>
 *
 * Based on vmcs_sm driver from Broadcom Corporation for some API,
 * and taking some code for buffer allocation and dmabuf handling from
 * videobuf2.
 *
 * This driver has 3 main uses:
 * 1) Allocating buffers for the kernel or userspace that can be shared with the
 *    VPU.
 * 2) Importing dmabufs from elsewhere for sharing with the VPU.
 * 3) Allocating buffers for use by the VPU.
 *
 * In the first and second cases the native handle is a dmabuf. Releasing the
 * resource inherently comes from releasing the dmabuf, and this will trigger
 * unmapping on the VPU. The underlying allocation and our buffer structure are
 * retained until the VPU has confirmed that it has finished with it.
 *
 * For the VPU allocations the VPU is responsible for triggering the release,
 * and therefore the released message decrements the dma_buf refcount (with the
 * VPU mapping having already been marked as released).
 */

#include <linux/device.h>
#include <linux/debugfs.h>
#include <linux/dma-mapping.h>
#include <linux/dma-buf.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/of_device.h>
#include <linux/raspberrypi/vchiq_arm.h>
#include <linux/raspberrypi/vchiq_bus.h>
#include <linux/raspberrypi/vc_sm_cma_ioctl.h>
#include <linux/raspberrypi/vc_sm_knl.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/xarray.h>

#include "vc_sm_cma_vchi.h"
#include "vc_sm_defs.h"

#include "vc_sm.h"

MODULE_IMPORT_NS("DMA_BUF");

#define DEVICE_NAME		"vcsm-cma"
#define DEVICE_MINOR		0

#define VC_SM_RESOURCE_NAME_DEFAULT       "sm-host-resource"

#define VC_SM_DIR_ROOT_NAME	"vcsm-cma"
#define VC_SM_STATE		"state"

/* VC4 address aliases for the lower 1GB of RAM. */
#define VC_SM_VC4_ALIAS_MASK		0xc0000000
#define VC_SM_VC4_UNCACHED_ALIAS	0xc0000000
/* L2 coherent, non-alocating */
#define VC_SM_VC4_COHERENT_ALIAS	0x80000000

struct sm_pde_t {
	int (*show)(struct seq_file *s, void *v); /* Debug fs fn hookup */
	struct dentry *dir_entry;		  /* Debug fs directory entry */
	void *priv_data;			  /* Private data */
};

/* Global state information. */
struct sm_state_t {
	struct vchiq_device *device;

	struct miscdevice misc_dev;

	struct sm_instance *sm_handle;	/* Handle for videocore service. */

	struct xarray kernelid_map;

	struct mutex map_lock;          /* Global map lock. */
	struct list_head buffer_list;	/* List of buffer. */

	struct dentry *dir_root;	/* Debug fs entries root. */
	struct sm_pde_t dir_state;	/* Debug fs entries state sub-tree. */

	bool require_released_callback;	/* VPU will send a released msg when it
					 * has finished with a resource.
					 */
	/* State for transactions */
	int restart_sys;		/* Tracks restart on interrupt. */
	enum vc_sm_msg_type int_action;	/* Interrupted action. */
	u32 int_trans_id;		/* Interrupted transaction. */
	struct vchiq_instance *vchiq_instance;
};

struct vc_sm_dma_buf_attachment {
	struct device *dev;
	struct sg_table sg_table;
	struct list_head list;
	enum dma_data_direction	dma_dir;
};

static struct sm_state_t *sm_state;
static int sm_inited;

static int get_kernel_id(struct vc_sm_buffer *buffer)
{
	int handle, ret;

	ret = xa_alloc(&sm_state->kernelid_map, &handle, buffer, xa_limit_31b,
		       GFP_KERNEL);

	return ret < 0 ? ret : handle;
}

static struct vc_sm_buffer *lookup_kernel_id(int handle)
{
	return xa_load(&sm_state->kernelid_map, handle);
}

static void free_kernel_id(int handle)
{
	xa_erase(&sm_state->kernelid_map, handle);
}

static int vc_sm_cma_seq_file_show(struct seq_file *s, void *v)
{
	struct sm_pde_t *sm_pde;

	sm_pde = (struct sm_pde_t *)(s->private);

	if (sm_pde && sm_pde->show)
		sm_pde->show(s, v);

	return 0;
}

static int vc_sm_cma_single_open(struct inode *inode, struct file *file)
{
	return single_open(file, vc_sm_cma_seq_file_show, inode->i_private);
}

static const struct file_operations vc_sm_cma_debug_fs_fops = {
	.open = vc_sm_cma_single_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int vc_sm_cma_global_state_show(struct seq_file *s, void *v)
{
	struct vc_sm_buffer *resource = NULL;
	int resource_count = 0;

	if (!sm_state)
		return 0;

	/* Log all applicable mapping(s). */

	mutex_lock(&sm_state->map_lock);
	seq_puts(s, "\nResources\n");
	if (!list_empty(&sm_state->buffer_list)) {
		list_for_each_entry(resource, &sm_state->buffer_list,
				    global_buffer_list) {
			resource_count++;

			seq_printf(s, "\nResource                %p\n",
				   resource);
			seq_printf(s, "           NAME         %s\n",
				   resource->name);
			seq_printf(s, "           SIZE         %zu\n",
				   resource->size);
			seq_printf(s, "           DMABUF       %p\n",
				   resource->dma_buf);
			seq_printf(s, "           IMPORTED_DMABUF %p\n",
				   resource->imported_dma_buf);
			seq_printf(s, "           ATTACH       %p\n",
				   resource->attach);
			seq_printf(s, "           SGT          %p\n",
				   resource->sgt);
			seq_printf(s, "           DMA_ADDR     %pad\n",
				   &resource->dma_addr);
			seq_printf(s, "           VC_HANDLE     %08x\n",
				   resource->vc_handle);
			seq_printf(s, "           VC_MAPPING    %d\n",
				   resource->vpu_state);
		}
	}
	seq_printf(s, "\n\nTotal resource count:   %d\n\n", resource_count);

	mutex_unlock(&sm_state->map_lock);

	return 0;
}

/*
 * Adds a buffer to the private data list which tracks all the allocated
 * data.
 */
static void vc_sm_add_resource(struct vc_sm_buffer *buffer)
{
	mutex_lock(&sm_state->map_lock);
	list_add(&buffer->global_buffer_list, &sm_state->buffer_list);
	mutex_unlock(&sm_state->map_lock);
}

/*
 * Cleans up imported dmabuf.
 * Should be called with mutex held.
 */
static void vc_sm_clean_up_dmabuf(struct vc_sm_buffer *buffer)
{
	/* Handle cleaning up imported dmabufs */
	if (buffer->sgt) {
		dma_buf_unmap_sgt_unlocked(buffer->attach, buffer->sgt,
					   DMA_BIDIRECTIONAL);
		buffer->sgt = NULL;
	}
	if (buffer->attach) {
		dma_buf_detach(buffer->imported_dma_buf, buffer->attach);
		buffer->attach = NULL;
	}
}

/*
 * Instructs VPU to decrement the refcount on a buffer.
 */
static void vc_sm_vpu_free(struct vc_sm_buffer *buffer)
{
	if (buffer->vc_handle && buffer->vpu_state == VPU_MAPPED) {
		struct vc_sm_free_t free = { buffer->vc_handle, 0 };
		int status = vc_sm_cma_vchi_free(sm_state->sm_handle, &free,
					     &sm_state->int_trans_id);
		if (status != 0 && status != -EINTR) {
			dev_err(&sm_state->device->dev,
				"%s: failed to free memory on videocore (status: %u, trans_id: %u)\n",
				__func__, status, sm_state->int_trans_id);
		}

		if (sm_state->require_released_callback) {
			/*
			 * Need to wait for the VPU to confirm the free. Retain
			 * a reference on this until the VPU has released it
			 */
			buffer->vpu_state = VPU_UNMAPPING;
		} else {
			buffer->vpu_state = VPU_NOT_MAPPED;
			buffer->vc_handle = 0;
		}
	}
}

/*
 * Release an allocation.
 * All refcounting is done via the dma buf object.
 *
 * Must be called with the mutex held. The function will either release the
 * mutex (if defering the release) or destroy it. The caller must therefore not
 * reuse the buffer on return.
 */
static void vc_sm_release_resource(struct vc_sm_buffer *buffer)
{
	/* We've sent the unmap request but not had the response. */
	if (buffer->vc_handle)
		goto defer;
	/* dmabuf still in use - we await the release */
	if (buffer->in_use)
		goto defer;

	/* Release the allocation */
	if (buffer->imported_dma_buf)
		dma_buf_put(buffer->imported_dma_buf);
	else
		dev_err(&sm_state->device->dev, "%s: Imported dmabuf already been put for buf %p\n",
			__func__, buffer);
	buffer->imported_dma_buf = NULL;

	/* Free our buffer. Start by removing it from the list */
	mutex_lock(&sm_state->map_lock);
	list_del(&buffer->global_buffer_list);
	mutex_unlock(&sm_state->map_lock);

	mutex_unlock(&buffer->lock);
	mutex_destroy(&buffer->lock);

	kfree(buffer);
	return;

defer:
	mutex_unlock(&buffer->lock);
}

static void vc_sm_dma_buf_release(struct dma_buf *dmabuf)
{
	struct vc_sm_buffer *buffer;

	if (!dmabuf)
		return;

	buffer = (struct vc_sm_buffer *)dmabuf->priv;

	mutex_lock(&buffer->lock);

	buffer->in_use = false;

	/* Unmap on the VPU */
	vc_sm_vpu_free(buffer);

	/*
	 * Unmap our dma_buf object (the vc_sm_buffer remains until released
	 * on the VPU).
	 */
	vc_sm_clean_up_dmabuf(buffer);

	/*
	 * buffer->lock will be destroyed by vc_sm_release_resource if finished
	 * with, otherwise unlocked. Do NOT unlock here.
	 */
	vc_sm_release_resource(buffer);
}

/* Dma_buf operations for chaining through to an imported dma_buf */

static
int vc_sm_import_dma_buf_attach(struct dma_buf *dmabuf,
				struct dma_buf_attachment *attachment)
{
	struct vc_sm_buffer *buf = dmabuf->priv;

	return buf->imported_dma_buf->ops->attach(buf->imported_dma_buf,
						attachment);
}

static
void vc_sm_import_dma_buf_detatch(struct dma_buf *dmabuf,
				  struct dma_buf_attachment *attachment)
{
	struct vc_sm_buffer *buf = dmabuf->priv;

	buf->imported_dma_buf->ops->detach(buf->imported_dma_buf, attachment);
}

static
struct sg_table *vc_sm_import_map_dma_buf(struct dma_buf_attachment *attachment,
					  enum dma_data_direction direction)
{
	struct vc_sm_buffer *buf = attachment->dmabuf->priv;

	return buf->imported_dma_buf->ops->map_dma_buf(attachment,
						     direction);
}

static
void vc_sm_import_unmap_dma_buf(struct dma_buf_attachment *attachment,
				struct sg_table *table,
				enum dma_data_direction direction)
{
	struct vc_sm_buffer *buf = attachment->dmabuf->priv;

	buf->imported_dma_buf->ops->unmap_dma_buf(attachment, table, direction);
}

static
int vc_sm_import_dmabuf_mmap(struct dma_buf *dmabuf, struct vm_area_struct *vma)
{
	struct vc_sm_buffer *buf = dmabuf->priv;

	return buf->imported_dma_buf->ops->mmap(buf->imported_dma_buf, vma);
}

static
int vc_sm_import_dma_buf_begin_cpu_access(struct dma_buf *dmabuf,
					  enum dma_data_direction direction)
{
	struct vc_sm_buffer *buf = dmabuf->priv;
	const struct dma_buf_ops *ops = buf->imported_dma_buf->ops;

	return ops->begin_cpu_access(buf->imported_dma_buf, direction);
}

static
int vc_sm_import_dma_buf_end_cpu_access(struct dma_buf *dmabuf,
					enum dma_data_direction direction)
{
	struct vc_sm_buffer *buf = dmabuf->priv;

	return buf->imported_dma_buf->ops->end_cpu_access(buf->imported_dma_buf,
							  direction);
}

static const struct dma_buf_ops dma_buf_import_ops = {
	.map_dma_buf = vc_sm_import_map_dma_buf,
	.unmap_dma_buf = vc_sm_import_unmap_dma_buf,
	.mmap = vc_sm_import_dmabuf_mmap,
	.release = vc_sm_dma_buf_release,
	.attach = vc_sm_import_dma_buf_attach,
	.detach = vc_sm_import_dma_buf_detatch,
	.begin_cpu_access = vc_sm_import_dma_buf_begin_cpu_access,
	.end_cpu_access = vc_sm_import_dma_buf_end_cpu_access,
};

/* Import a dma_buf to be shared with VC. */
static int
vc_sm_cma_import_dmabuf_internal(struct dma_buf *dma_buf,
				 int fd,
				 struct dma_buf **imported_buf)
{
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	struct dma_buf_attachment *attach = NULL;
	struct vc_sm_import_result result = { };
	struct vc_sm_buffer *buffer = NULL;
	struct vc_sm_import import = { };
	struct sg_table *sgt = NULL;
	dma_addr_t dma_addr;
	int kernel_id = -1;
	u32 cache_alias;
	int ret = 0;
	int status;

	/* Setup our allocation parameters */
	if (fd < 0)
		get_dma_buf(dma_buf);
	else
		dma_buf = dma_buf_get(fd);

	if (!dma_buf)
		return -EINVAL;

	attach = dma_buf_attach(dma_buf, &sm_state->device->dev);
	if (IS_ERR(attach)) {
		ret = PTR_ERR(attach);
		goto error;
	}

	sgt = dma_buf_map_sgt_unlocked(attach, DMA_BIDIRECTIONAL);
	if (IS_ERR(sgt)) {
		ret = PTR_ERR(sgt);
		goto error;
	}

	/* Verify that the address block is contiguous */
	if (sgt->nents != 1) {
		ret = -ENOMEM;
		goto error;
	}

	/* Allocate local buffer to track this allocation. */
	buffer = kzalloc(sizeof(*buffer), GFP_KERNEL);
	if (!buffer) {
		ret = -ENOMEM;
		goto error;
	}

	import.type = VC_SM_ALLOC_NON_CACHED;
	dma_addr = sg_dma_address(sgt->sgl);
	import.addr = (u32)dma_addr;
	cache_alias = import.addr & VC_SM_VC4_ALIAS_MASK;
	if (cache_alias != VC_SM_VC4_UNCACHED_ALIAS &&
	    cache_alias != VC_SM_VC4_COHERENT_ALIAS) {
		dev_err(&sm_state->device->dev, "%s: Expecting an uncached alias for dma_addr %pad\n",
			__func__, &dma_addr);
		/*
		 * Note that this assumes we're on >= Pi2, but it implies a
		 * DT configuration error.
		 */
		import.addr |= VC_SM_VC4_UNCACHED_ALIAS;
	}
	import.size = sg_dma_len(sgt->sgl);
	import.allocator = current->tgid;
	kernel_id = get_kernel_id(buffer);
	if (kernel_id < 0) {
		ret = kernel_id;
		goto error;
	}
	import.kernel_id = kernel_id;

	memcpy(import.name, VC_SM_RESOURCE_NAME_DEFAULT,
	       sizeof(VC_SM_RESOURCE_NAME_DEFAULT));

	/* Allocate the videocore buffer. */
	status = vc_sm_cma_vchi_import(sm_state->sm_handle, &import, &result,
				       &sm_state->int_trans_id);
	if (status == -EINTR) {
		dev_dbg(&sm_state->device->dev,
			"%s: requesting import memory action restart (trans_id: %u)\n",
			__func__, sm_state->int_trans_id);
		ret = -ERESTARTSYS;
		sm_state->restart_sys = -EINTR;
		sm_state->int_action = VC_SM_MSG_TYPE_IMPORT;
		goto error;
	} else if (status || !result.res_handle) {
		dev_dbg(&sm_state->device->dev,
			"%s: failed to import memory on videocore (status: %u, trans_id: %u)\n",
			 __func__, status, sm_state->int_trans_id);
		ret = -ENOMEM;
		goto error;
	}

	mutex_init(&buffer->lock);
	INIT_LIST_HEAD(&buffer->attachments);
	memcpy(buffer->name, import.name,
	       min(sizeof(buffer->name), sizeof(import.name) - 1));

	/* Keep track of the buffer we created. */
	buffer->vc_handle = result.res_handle;
	buffer->size = import.size;
	buffer->vpu_state = VPU_MAPPED;

	buffer->imported_dma_buf = dma_buf;

	buffer->attach = attach;
	buffer->sgt = sgt;
	buffer->dma_addr = dma_addr;
	buffer->in_use = true;
	buffer->kernel_id = import.kernel_id;

	/*
	 * We're done - we need to export a new dmabuf chaining through most
	 * functions, but enabling us to release our own internal references
	 * here.
	 */
	exp_info.ops = &dma_buf_import_ops;
	exp_info.size = import.size;
	exp_info.flags = O_RDWR;
	exp_info.priv = buffer;

	buffer->dma_buf = dma_buf_export(&exp_info);
	if (IS_ERR(buffer->dma_buf)) {
		ret = PTR_ERR(buffer->dma_buf);
		goto error;
	}

	vc_sm_add_resource(buffer);

	*imported_buf = buffer->dma_buf;

	return 0;

error:
	if (result.res_handle) {
		struct vc_sm_free_t free = { result.res_handle, 0 };

		vc_sm_cma_vchi_free(sm_state->sm_handle, &free,
				    &sm_state->int_trans_id);
	}
	if (kernel_id >= 0)
		free_kernel_id(import.kernel_id);
	kfree(buffer);
	if (sgt)
		dma_buf_unmap_sgt_unlocked(attach, sgt, DMA_BIDIRECTIONAL);
	if (attach)
		dma_buf_detach(dma_buf, attach);
	dma_buf_put(dma_buf);
	return ret;
}

static void
vc_sm_vpu_event(struct sm_instance *instance, struct vc_sm_result_t *reply,
		int reply_len)
{
	switch (reply->trans_id & ~VC_SM_TRANS_ID_VPU_FLAG) {
	case VC_SM_MSG_TYPE_CLIENT_VERSION:
	{
		/* Acknowledge that the firmware supports the version command */
		sm_state->require_released_callback = true;
	}
	break;
	case VC_SM_MSG_TYPE_RELEASED:
	{
		struct vc_sm_released *release = (struct vc_sm_released *)reply;
		struct vc_sm_buffer *buffer =
					lookup_kernel_id(release->kernel_id);
		if (!buffer) {
			dev_err(&sm_state->device->dev,
				"%s: VC released a buffer that is already released, kernel_id %d\n",
				__func__, release->kernel_id);
			break;
		}
		mutex_lock(&buffer->lock);

		dev_dbg(&sm_state->device->dev,
			"%s: Released addr %08x, size %u, id %08x, mem_handle %08x\n",
			__func__, release->addr, release->size,
			release->kernel_id, release->vc_handle);

		buffer->vc_handle = 0;
		buffer->vpu_state = VPU_NOT_MAPPED;
		free_kernel_id(release->kernel_id);

		vc_sm_release_resource(buffer);
	}
	break;
	default:
		dev_err(&sm_state->device->dev, "%s: Unknown vpu cmd %x\n",
			__func__, reply->trans_id);
		break;
	}
}

/* Driver load/unload functions */
static void vc_sm_connected_init(void)
{
	struct vc_sm_result_t version_result;
	struct vc_sm_version version;
	int ret;

	/*
	 * Digging the vchiq_drv_mgmt, so low here and through a global seems
	 * suspicious.
	 *
	 * The callbacks should be able to pass a parameter or context.
	 */
	struct vchiq_drv_mgmt *mgmt =
		dev_get_drvdata(sm_state->device->dev.parent);

	/*
	 * Initialize and create a VCHI connection for the shared memory service
	 * running on videocore.
	 */
	ret = vchiq_initialise(&mgmt->state, &sm_state->vchiq_instance);
	if (ret) {
		dev_err(&sm_state->device->dev,
			"%s: failed to initialise VCHI instance (ret=%d)\n",
			__func__, ret);

		return;
	}

	ret = vchiq_connect(sm_state->vchiq_instance);
	if (ret) {
		dev_err(&sm_state->device->dev,
			"%s: failed to connect VCHI instance (ret=%d)\n",
			__func__, ret);

		return;
	}

	/* Initialize an instance of the shared memory service. */
	sm_state->sm_handle = vc_sm_cma_vchi_init(sm_state->vchiq_instance, 1,
						  vc_sm_vpu_event);
	if (!sm_state->sm_handle) {
		dev_err(&sm_state->device->dev,
			"%s: failed to initialize shared memory service\n",
			__func__);

		return;
	}

	/* Create a debug fs directory entry (root). */
	sm_state->dir_root = debugfs_create_dir(VC_SM_DIR_ROOT_NAME, NULL);

	sm_state->dir_state.show = &vc_sm_cma_global_state_show;
	sm_state->dir_state.dir_entry =
		debugfs_create_file(VC_SM_STATE, 0444, sm_state->dir_root,
				    &sm_state->dir_state,
				    &vc_sm_cma_debug_fs_fops);

	INIT_LIST_HEAD(&sm_state->buffer_list);

	version.version = 2;
	ret = vc_sm_cma_vchi_client_version(sm_state->sm_handle, &version,
					    &version_result,
					    &sm_state->int_trans_id);
	if (ret) {
		dev_err(&sm_state->device->dev,
			"%s: Failed to send version request %d\n", __func__,
			ret);
	}

	sm_inited = 1;
}

static int bcm2835_vc_sm_cma_probe(struct vchiq_device *device)
{
	int err;

	err = dma_set_mask_and_coherent(&device->dev, DMA_BIT_MASK(32));
	if (err) {
		dev_err(&device->dev, "dma_set_mask_and_coherent failed: %d\n",
			err);
		return err;
	}

	sm_state = devm_kzalloc(&device->dev, sizeof(*sm_state), GFP_KERNEL);
	if (!sm_state)
		return -ENOMEM;
	sm_state->device = device;
	mutex_init(&sm_state->map_lock);

	xa_init_flags(&sm_state->kernelid_map, XA_FLAGS_ALLOC1);

	device->dev.dma_parms = devm_kzalloc(&device->dev,
					     sizeof(*device->dev.dma_parms),
					     GFP_KERNEL);
	/* dma_set_max_seg_size checks if dma_parms is NULL. */
	dma_set_max_seg_size(&device->dev, 0x3FFFFFFF);

	vchiq_add_connected_callback(device, vc_sm_connected_init);
	return 0;
}

static void bcm2835_vc_sm_cma_remove(struct vchiq_device *device)
{
	if (sm_inited) {
		misc_deregister(&sm_state->misc_dev);

		/* Remove all proc entries. */
		debugfs_remove_recursive(sm_state->dir_root);

		/* Stop the videocore shared memory service. */
		vc_sm_cma_vchi_stop(sm_state->vchiq_instance,
				    &sm_state->sm_handle);
	}

	if (sm_state) {
		xa_destroy(&sm_state->kernelid_map);

		/* Free the memory for the state structure. */
		mutex_destroy(&sm_state->map_lock);
	}
}

/* Get an internal resource handle mapped from the external one. */
int vc_sm_cma_get_vc_handle(void *handle)
{
	struct dma_buf *dma_buf = (struct dma_buf *)handle;
	struct vc_sm_buffer *buf;

	/* Validate we can work with this device. */
	if (!sm_state || !handle) {
		pr_err("%s: invalid input\n", __func__);
		return 0;
	}

	buf = (struct vc_sm_buffer *)dma_buf->priv;
	return buf->vc_handle;
}
EXPORT_SYMBOL_GPL(vc_sm_cma_get_vc_handle);

/* Free a previously allocated shared memory handle and block. */
int vc_sm_cma_free(void *handle)
{
	struct dma_buf *dma_buf = (struct dma_buf *)handle;

	/* Validate we can work with this device. */
	if (!sm_state || !handle) {
		pr_err("%s: invalid input\n", __func__);
		return -EPERM;
	}

	dma_buf_put(dma_buf);

	return 0;
}
EXPORT_SYMBOL_GPL(vc_sm_cma_free);

/* Import a dmabuf to be shared with VC. */
int vc_sm_cma_import_dmabuf(struct dma_buf *src_dmabuf, void **handle)
{
	struct dma_buf *new_dma_buf;
	int ret;

	/* Validate we can work with this device. */
	if (!sm_state || !src_dmabuf || !handle) {
		pr_err("%s: invalid input\n", __func__);
		return -EPERM;
	}

	ret = vc_sm_cma_import_dmabuf_internal(src_dmabuf, -1, &new_dma_buf);

	if (!ret) {
		/* Assign valid handle at this time.*/
		*handle = new_dma_buf;
	} else {
		/*
		 * succeeded in importing the dma_buf, but then
		 * failed to look it up again. How?
		 * Release the fd again.
		 */
		dev_err(&sm_state->device->dev,
			"%s: imported vc_sm_cma_get_buffer failed %d\n",
			__func__, ret);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(vc_sm_cma_import_dmabuf);

static struct vchiq_device_id device_id_table[] = {
	{ .name = "vcsm-cma" },
	{}
};
MODULE_DEVICE_TABLE(vchiq, device_id_table);

static struct vchiq_driver bcm2835_vcsm_cma_driver = {
	.probe = bcm2835_vc_sm_cma_probe,
	.remove = bcm2835_vc_sm_cma_remove,
	.id_table = device_id_table,
	.driver = {
		.name = DEVICE_NAME,
		.owner = THIS_MODULE,
	},
};

module_vchiq_driver(bcm2835_vcsm_cma_driver);

MODULE_AUTHOR("Dave Stevenson");
MODULE_DESCRIPTION("VideoCore CMA Shared Memory Driver");
MODULE_LICENSE("GPL");
