/* SPDX-License-Identifier: GPL-2.0 */
/*
 * (C) COPYRIGHT 2016 ARM Limited. All rights reserved.
 * Author: Brian Starkey <brian.starkey@arm.com>
 *
 * This program is free software and is provided to you under the terms of the
 * GNU General Public License version 2 as published by the Free Software
 * Foundation, and any use by you of this program is subject to the terms
 * of such GNU licence.
 */

#ifndef __DRM_WRITEBACK_H__
#define __DRM_WRITEBACK_H__
#include <drm/drm_connector.h>
#include <drm/drm_encoder.h>
#include <linux/workqueue.h>

/**
 * struct drm_writeback_job - DRM writeback job
 */
struct drm_writeback_job {
	/**
	 * @connector:
	 *
	 * Back-pointer to the writeback connector associated with the job
	 */
	struct drm_writeback_connector *connector;

	/**
	 * @prepared:
	 *
	 * Set when the job has been prepared with drm_writeback_prepare_job()
	 */
	bool prepared;

	/**
	 * @cleanup_work:
	 *
	 * Used to allow drm_writeback_signal_completion to defer dropping the
	 * framebuffer reference to a workqueue
	 */
	struct work_struct cleanup_work;

	/**
	 * @list_entry:
	 *
	 * List item for the writeback connector's @job_queue
	 */
	struct list_head list_entry;

	/**
	 * @fb:
	 *
	 * Framebuffer to be written to by the writeback connector. Do not set
	 * directly, use drm_writeback_set_fb()
	 */
	struct drm_framebuffer *fb;

	/**
	 * @out_fence:
	 *
	 * Fence which will signal once the writeback has completed
	 */
	struct dma_fence *out_fence;

	/**
	 * @priv:
	 *
	 * Driver-private data
	 */
	void *priv;
};

static inline struct drm_connector *
drm_writeback_to_connector(struct drm_writeback_connector *wb_connector)
{
	return container_of(wb_connector, struct drm_connector, writeback);
}

int drm_writeback_connector_init(struct drm_device *dev,
				 struct drm_connector *connector,
				 const struct drm_connector_funcs *con_funcs,
				 struct drm_encoder *enc,
				 const u32 *formats, int n_formats);

int drmm_writeback_connector_init(struct drm_device *dev,
				  struct drm_connector *connector,
				  const struct drm_connector_funcs *con_funcs,
				  struct drm_encoder *enc,
				  const u32 *formats, int n_formats);

int drm_writeback_set_fb(struct drm_connector_state *conn_state,
			 struct drm_framebuffer *fb);

int drm_writeback_prepare_job(struct drm_writeback_job *job);

void drm_writeback_queue_job(struct drm_connector *wb_connector,
			     struct drm_connector_state *conn_state);

void drm_writeback_cleanup_job(struct drm_writeback_job *job);

void
drm_writeback_signal_completion(struct drm_connector *connector,
				int status);

struct dma_fence *
drm_writeback_get_out_fence(struct drm_connector *connector);
#endif
