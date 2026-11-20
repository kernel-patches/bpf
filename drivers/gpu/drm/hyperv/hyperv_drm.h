/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright 2021 Microsoft
 */

#ifndef _HYPERV_DRM_H_
#define _HYPERV_DRM_H_

#include <drm/drm_connector.h>
#include <drm/drm_crtc.h>
#include <drm/drm_encoder.h>
#include <drm/drm_plane.h>

#define VMBUS_MAX_PACKET_SIZE 0x4000

#define SYNTHVID_CURSOR_MAX_X 96
#define SYNTHVID_CURSOR_MAX_Y 96
#define SYNTHVID_CURSOR_ARGB_PIXEL_SIZE 4
#define SYNTHVID_CURSOR_MAX_SIZE (SYNTHVID_CURSOR_MAX_X * \
	SYNTHVID_CURSOR_MAX_Y * SYNTHVID_CURSOR_ARGB_PIXEL_SIZE)

/*
 * Copy of the cursor last handed to the host, so that it can be sent again
 * when needed, e.g. after a VM Connection window was opened.
 */
struct hv_drm_cursor {
	/* Serializes pointer messages and protects the fields below */
	struct mutex lock;
	/* The host may not have the cached shape, e.g. after a failed send */
	bool shape_stale;
	u32 width;
	u32 height;
	u32 hot_x;
	u32 hot_y;
	s32 x;
	s32 y;
	/* ARGB8888, rows of width pixels, stored bottom-up as the host wants */
	u8 image[SYNTHVID_CURSOR_MAX_SIZE];
	/* Scratch space for building pointer shape messages */
	u8 msg_buf[VMBUS_MAX_PACKET_SIZE];
};

struct hv_drm_device {
	/* drm */
	struct drm_device dev;
	struct drm_plane plane;
	struct drm_plane cursor_plane;
	struct drm_crtc crtc;
	struct drm_encoder encoder;
	struct drm_connector connector;

	/* mode */
	u32 screen_width_max;
	u32 screen_height_max;
	u32 preferred_width;
	u32 preferred_height;
	u32 screen_depth;

	/* hw */
	struct resource *mem;
	void __iomem *vram;
	unsigned long fb_base;
	unsigned long fb_size;
	struct completion wait;
	u32 mmio_megabytes;
	bool dirt_needed;

	u8 init_buf[VMBUS_MAX_PACKET_SIZE];
	u8 recv_buf[VMBUS_MAX_PACKET_SIZE];

	struct hv_drm_cursor *cursor;
	struct work_struct cursor_work;

	struct hv_device *hdev;
};

#define to_hv_drm(_dev) container_of(_dev, struct hv_drm_device, dev)

/* hyperv_drm_modeset */
int hv_drm_mode_config_init(struct hv_drm_device *hv);

/* hyperv_drm_proto */
int hv_drm_update_vram_location(struct hv_device *hdev, phys_addr_t vram_pp);
int hv_drm_update_situation(struct hv_device *hdev, u8 active, u32 bpp,
			    u32 w, u32 h, u32 pitch);
int hv_drm_cursor_init(struct hv_drm_device *hv);
void hv_drm_cursor_set_hidden(struct hv_drm_cursor *cursor);
void hv_drm_update_cursor(struct hv_drm_device *hv, bool shape);
void hv_drm_restore_cursor(struct hv_drm_device *hv);
int hv_drm_update_dirt(struct hv_device *hdev, struct drm_rect *rect);
int hv_drm_connect_vsp(struct hv_device *hdev);
void hv_drm_disconnect_vsp(struct hv_device *hdev);

#endif
