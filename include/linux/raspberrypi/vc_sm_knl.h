/* SPDX-License-Identifier: GPL-2.0 */

/*
 * VideoCore Shared Memory CMA allocator
 *
 * Copyright: 2018, Raspberry Pi (Trading) Ltd
 *
 * Based on vc_sm_defs.h from the vmcs_sm driver Copyright Broadcom Corporation.
 *
 */

#ifndef __VC_SM_KNL_H__INCLUDED__
#define __VC_SM_KNL_H__INCLUDED__

#include <linux/dma-buf.h>

/**
 * vc_sm_cma_free() - Release a VideoCore shared memory buffer
 * @handle: Pointer to dmabuf representing the buffer to free
 *
 * This function should be called to release handles obtained from
 * vc_sm_cma_import_dmabuf(). It decrements the dmabuf reference count,
 * which triggers the cleanup sequence if this was the last reference.
 *
 * The actual memory deallocation is deferred until both the ARM-side
 * references are released AND VideoCore confirms it has finished accessing
 * the buffer. This ensures safe cleanup even if VideoCore operations are
 * still in progress.
 *
 * Returns 0 on success, -%EPERM if the device is not initialized or handle is
 * invalid.
 */
int vc_sm_cma_free(void *handle);

/**
 * vc_sm_cma_get_vc_handle() - Get VideoCore handle from dmabuf handle
 * @handle: Pointer to dmabuf representing the shared memory buffer
 *
 * This function retrieves the VideoCore firmware handle associated with
 * a dmabuf that was previously allocated or imported through this driver.
 * The VideoCore handle is required when communicating with VideoCore
 * firmware to reference the shared buffer.
 *
 * The handle parameter must be a dmabuf pointer that was obtained from
 * either vc_sm_cma_import_dmabuf() or through the /dev/vcsm-cma device
 * allocation ioctls.
 *
 * Returns VideoCore handle (non-zero) on success, 0 on failure or invalid
 * input.
 */
int vc_sm_cma_get_vc_handle(void *handle);

/**
 * vc_sm_cma_import_dmabuf() - Import a dmabuf for sharing with VideoCore
 * @src_dmabuf: DMA-BUF to import
 * @handle: Output pointer to receive the new dmabuf handle
 *
 * Imports an existing dmabuf into the VideoCore shared memory subsystem,
 * making it accessible to VideoCore firmware. This allows sharing of
 * buffers allocated by other kernel drivers (such as V4L2) with VideoCore.
 *
 * The returned handle must be freed with vc_sm_cma_free() when no longer
 * needed. The handle can be passed to vc_sm_cma_int_handle() to obtain
 * the VideoCore firmware handle for use in MMAL or other VideoCore APIs.
 *
 * The imported buffer must be physically contiguous and located in memory
 * addressable by VideoCore.
 *
 * Returns 0 on success and @handle is set to the new dmabuf pointer,
 *         -%EPERM if the device is not initialized or input is invalid,
 *         -%ENOMEM if allocation fails,
 *         -%ERESTARTSYS if interrupted by signal during VCHI communication.
 */
int vc_sm_cma_import_dmabuf(struct dma_buf *dmabuf, void **handle);

#endif /* __VC_SM_KNL_H__INCLUDED__ */
