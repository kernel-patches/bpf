// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2021 Microsoft
 */

#include <linux/hyperv.h>

#include <drm/drm_managed.h>
#include <drm/drm_print.h>

#include "hyperv_drm.h"

#define VMBUS_RING_BUFSIZE VMBUS_RING_SIZE(256 * 1024)
#define VMBUS_VSP_TIMEOUT (10 * HZ)

#define SYNTHVID_VERSION(major, minor) ((minor) << 16 | (major))
#define SYNTHVID_VER_GET_MAJOR(ver) (ver & 0x0000ffff)
#define SYNTHVID_VER_GET_MINOR(ver) ((ver & 0xffff0000) >> 16)

/* Support for WIN7 and WIN8 is removed. #define's retained for reference. */
#define SYNTHVID_VERSION_WIN7 SYNTHVID_VERSION(3, 0)
#define SYNTHVID_VERSION_WIN8 SYNTHVID_VERSION(3, 2)
#define SYNTHVID_VERSION_WIN10 SYNTHVID_VERSION(3, 5)

#define SYNTHVID_DEPTH_WIN8 32
#define SYNTHVID_WIDTH_WIN8 1600
#define SYNTHVID_HEIGHT_WIN8 1200
#define SYNTHVID_FB_SIZE_WIN8 (8 * 1024 * 1024)

enum pipe_msg_type {
	PIPE_MSG_INVALID,
	PIPE_MSG_DATA,
	PIPE_MSG_MAX
};

enum synthvid_msg_type {
	SYNTHVID_ERROR			= 0,
	SYNTHVID_VERSION_REQUEST	= 1,
	SYNTHVID_VERSION_RESPONSE	= 2,
	SYNTHVID_VRAM_LOCATION		= 3,
	SYNTHVID_VRAM_LOCATION_ACK	= 4,
	SYNTHVID_SITUATION_UPDATE	= 5,
	SYNTHVID_SITUATION_UPDATE_ACK	= 6,
	SYNTHVID_POINTER_POSITION	= 7,
	SYNTHVID_POINTER_SHAPE		= 8,
	SYNTHVID_FEATURE_CHANGE		= 9,
	SYNTHVID_DIRT			= 10,
	SYNTHVID_RESOLUTION_REQUEST	= 13,
	SYNTHVID_RESOLUTION_RESPONSE	= 14,

	SYNTHVID_MAX			= 15
};

struct pipe_msg_hdr {
	u32 type;
	u32 size; /* size of message after this field */
} __packed;

struct hvd_screen_info {
	u16 width;
	u16 height;
} __packed;

struct synthvid_msg_hdr {
	u32 type;
	u32 size;  /* size of this header + payload after this field */
} __packed;

struct synthvid_version_req {
	u32 version;
} __packed;

struct synthvid_version_resp {
	u32 version;
	u8 is_accepted;
	u8 max_video_outputs;
} __packed;

struct synthvid_vram_location {
	u64 user_ctx;
	u8 is_vram_gpa_specified;
	u64 vram_gpa;
} __packed;

struct synthvid_vram_location_ack {
	u64 user_ctx;
} __packed;

struct video_output_situation {
	u8 active;
	u32 vram_offset;
	u8 depth_bits;
	u32 width_pixels;
	u32 height_pixels;
	u32 pitch_bytes;
} __packed;

struct synthvid_situation_update {
	u64 user_ctx;
	u8 video_output_count;
	struct video_output_situation video_output[1];
} __packed;

struct synthvid_situation_update_ack {
	u64 user_ctx;
} __packed;

struct synthvid_pointer_position {
	u8 is_visible;
	u8 video_output;
	s32 image_x;
	s32 image_y;
} __packed;

#define SYNTHVID_CURSOR_COMPLETE (-1)
/* Most pixel data the host accepts in one pointer shape message */
#define SYNTHVID_CURSOR_MAX_PAYLOAD 8192

struct synthvid_pointer_shape {
	u8 part_idx;
	u8 is_argb;
	u32 width; /* SYNTHVID_CURSOR_MAX_X at most */
	u32 height; /* SYNTHVID_CURSOR_MAX_Y at most */
	u32 hot_x; /* hotspot relative to upper-left of pointer image */
	u32 hot_y;
	u8 data[4];
} __packed;

struct synthvid_feature_change {
	u8 is_dirt_needed;
	u8 is_ptr_pos_needed;
	u8 is_ptr_shape_needed;
	u8 is_situ_needed;
} __packed;

struct rect {
	s32 x1, y1; /* top left corner */
	s32 x2, y2; /* bottom right corner, exclusive */
} __packed;

struct synthvid_dirt {
	u8 video_output;
	u8 dirt_count;
	struct rect rect[1];
} __packed;

#define SYNTHVID_EDID_BLOCK_SIZE	128
#define	SYNTHVID_MAX_RESOLUTION_COUNT	64

struct synthvid_supported_resolution_req {
	u8 maximum_resolution_count;
} __packed;

struct synthvid_supported_resolution_resp {
	u8 edid_block[SYNTHVID_EDID_BLOCK_SIZE];
	u8 resolution_count;
	u8 default_resolution_index;
	u8 is_standard;
	struct hvd_screen_info supported_resolution[SYNTHVID_MAX_RESOLUTION_COUNT];
} __packed;

struct synthvid_msg {
	struct pipe_msg_hdr pipe_hdr;
	struct synthvid_msg_hdr vid_hdr;
	union {
		struct synthvid_version_req ver_req;
		struct synthvid_version_resp ver_resp;
		struct synthvid_vram_location vram;
		struct synthvid_vram_location_ack vram_ack;
		struct synthvid_situation_update situ;
		struct synthvid_situation_update_ack situ_ack;
		struct synthvid_pointer_position ptr_pos;
		struct synthvid_pointer_shape ptr_shape;
		struct synthvid_feature_change feature_chg;
		struct synthvid_dirt dirt;
		struct synthvid_supported_resolution_req resolution_req;
		struct synthvid_supported_resolution_resp resolution_resp;
	};
} __packed;

static inline int hv_drm_sendpacket(struct hv_device *hdev, struct synthvid_msg *msg)
{
	static atomic64_t request_id = ATOMIC64_INIT(0);
	struct hv_drm_device *hv = hv_get_drvdata(hdev);
	int ret;

	msg->pipe_hdr.type = PIPE_MSG_DATA;
	msg->pipe_hdr.size = msg->vid_hdr.size;

	ret = vmbus_sendpacket(hdev->channel, msg,
			       msg->vid_hdr.size + sizeof(struct pipe_msg_hdr),
			       atomic64_inc_return(&request_id),
			       VM_PKT_DATA_INBAND, 0);

	if (ret)
		drm_err_ratelimited(&hv->dev, "Unable to send packet via vmbus; error %d\n", ret);

	return ret;
}

static int hv_drm_negotiate_version(struct hv_device *hdev, u32 ver)
{
	struct hv_drm_device *hv = hv_get_drvdata(hdev);
	struct synthvid_msg *msg = (struct synthvid_msg *)hv->init_buf;
	struct drm_device *dev = &hv->dev;
	unsigned long t;

	memset(msg, 0, sizeof(struct synthvid_msg));
	msg->vid_hdr.type = SYNTHVID_VERSION_REQUEST;
	msg->vid_hdr.size = sizeof(struct synthvid_msg_hdr) +
		sizeof(struct synthvid_version_req);
	msg->ver_req.version = ver;
	hv_drm_sendpacket(hdev, msg);

	t = wait_for_completion_timeout(&hv->wait, VMBUS_VSP_TIMEOUT);
	if (!t) {
		drm_err(dev, "Time out on waiting version response\n");
		return -ETIMEDOUT;
	}

	if (!msg->ver_resp.is_accepted) {
		drm_err(dev, "Version request not accepted\n");
		return -ENODEV;
	}

	drm_info(dev, "Synthvid Version major %d, minor %d\n",
		 SYNTHVID_VER_GET_MAJOR(ver), SYNTHVID_VER_GET_MINOR(ver));

	return 0;
}

int hv_drm_update_vram_location(struct hv_device *hdev, phys_addr_t vram_pp)
{
	struct hv_drm_device *hv = hv_get_drvdata(hdev);
	struct synthvid_msg *msg = (struct synthvid_msg *)hv->init_buf;
	struct drm_device *dev = &hv->dev;
	unsigned long t;

	memset(msg, 0, sizeof(struct synthvid_msg));
	msg->vid_hdr.type = SYNTHVID_VRAM_LOCATION;
	msg->vid_hdr.size = sizeof(struct synthvid_msg_hdr) +
		sizeof(struct synthvid_vram_location);
	msg->vram.user_ctx = vram_pp;
	msg->vram.vram_gpa = vram_pp;
	msg->vram.is_vram_gpa_specified = 1;
	hv_drm_sendpacket(hdev, msg);

	t = wait_for_completion_timeout(&hv->wait, VMBUS_VSP_TIMEOUT);
	if (!t) {
		drm_err(dev, "Time out on waiting vram location ack\n");
		return -ETIMEDOUT;
	}
	if (msg->vram_ack.user_ctx != vram_pp) {
		drm_err(dev, "Unable to set VRAM location\n");
		return -ENODEV;
	}

	return 0;
}

int hv_drm_update_situation(struct hv_device *hdev, u8 active, u32 bpp,
			    u32 w, u32 h, u32 pitch)
{
	struct synthvid_msg msg;

	memset(&msg, 0, sizeof(struct synthvid_msg));

	msg.vid_hdr.type = SYNTHVID_SITUATION_UPDATE;
	msg.vid_hdr.size = sizeof(struct synthvid_msg_hdr) +
		sizeof(struct synthvid_situation_update);
	msg.situ.user_ctx = 0;
	msg.situ.video_output_count = 1;
	msg.situ.video_output[0].active = active;
	/* vram_offset should always be 0 */
	msg.situ.video_output[0].vram_offset = 0;
	msg.situ.video_output[0].depth_bits = bpp;
	msg.situ.video_output[0].width_pixels = w;
	msg.situ.video_output[0].height_pixels = h;
	msg.situ.video_output[0].pitch_bytes = pitch;

	hv_drm_sendpacket(hdev, &msg);

	return 0;
}

/*
 * The host always shows a mouse pointer: the one set with the pointer shape
 * and position messages, or else a small dot, which is also what it shows
 * for a pointer marked invisible. A hidden cursor is therefore a single,
 * almost transparent pixel.
 *
 * NOTE: Its alpha, the last byte, is 1 rather than 0, as clients may draw an
 *       image whose alpha values are all 0 as an opaque one.
 */
static const u8 hv_drm_cursor_hidden_pixel[SYNTHVID_CURSOR_ARGB_PIXEL_SIZE] = {
	0x00, 0x01, 0x01, 0x01
};

void hv_drm_cursor_set_hidden(struct hv_drm_cursor *cursor)
{
	memcpy(cursor->image, hv_drm_cursor_hidden_pixel,
	       sizeof(hv_drm_cursor_hidden_pixel));
	cursor->width = 1;
	cursor->height = 1;
	cursor->hot_x = 0;
	cursor->hot_y = 0;
	cursor->x = 0;
	cursor->y = 0;
}

/*
 * Pointer shapes too large for one message are sent in parts numbered from
 * 0, with SYNTHVID_CURSOR_COMPLETE marking the last part. A shape that fits
 * in one message is sent as a lone SYNTHVID_CURSOR_COMPLETE part.
 */
static int hv_drm_send_ptr_shape(struct hv_drm_device *hv, u32 width,
				 u32 height, u32 hot_x, u32 hot_y,
				 const u8 *image)
{
	const size_t data_offset = offsetof(struct synthvid_msg,
					    ptr_shape.data);
	size_t size = width * height * SYNTHVID_CURSOR_ARGB_PIXEL_SIZE;
	u8 *buf = hv->cursor->msg_buf;
	struct synthvid_msg *msg;
	size_t offset = 0;
	u8 part = 0;
	size_t len;
	int ret;

	BUILD_BUG_ON((offsetof(struct synthvid_msg, ptr_shape.data) +
		     SYNTHVID_CURSOR_MAX_PAYLOAD) >
		     sizeof_field(struct hv_drm_cursor, msg_buf));

	msg = (struct synthvid_msg *)buf;

	do {
		len = min(size - offset, SYNTHVID_CURSOR_MAX_PAYLOAD);

		memset(buf, 0, data_offset);
		msg->vid_hdr.type = SYNTHVID_POINTER_SHAPE;
		msg->vid_hdr.size = sizeof(struct synthvid_msg_hdr) +
			offsetof(struct synthvid_pointer_shape, data) + len;
		if (offset + len < size)
			msg->ptr_shape.part_idx = part++;
		else
			msg->ptr_shape.part_idx = SYNTHVID_CURSOR_COMPLETE;
		msg->ptr_shape.is_argb = 1;
		msg->ptr_shape.width = width;
		msg->ptr_shape.height = height;
		msg->ptr_shape.hot_x = hot_x;
		msg->ptr_shape.hot_y = hot_y;
		memcpy(buf + data_offset, image + offset, len);

		ret = hv_drm_sendpacket(hv->hdev, msg);
		if (ret)
			return ret;

		offset += len;
	} while (offset < size);

	return 0;
}

static int hv_drm_send_ptr_position(struct hv_drm_device *hv, s32 x, s32 y)
{
	struct synthvid_msg *msg = (struct synthvid_msg *)hv->cursor->msg_buf;

	memset(msg, 0, sizeof(struct synthvid_msg));
	msg->vid_hdr.type = SYNTHVID_POINTER_POSITION;
	msg->vid_hdr.size = sizeof(struct synthvid_msg_hdr) +
		sizeof(struct synthvid_pointer_position);
	msg->ptr_pos.is_visible = 1;
	msg->ptr_pos.video_output = 0;
	msg->ptr_pos.image_x = x;
	msg->ptr_pos.image_y = y;

	return hv_drm_sendpacket(hv->hdev, msg);
}

/*
 * Send the cached cursor to the host: the shape if @shape is set or the host
 * may lack it, then the position. The position goes last as the host applies
 * the hotspot of its current shape to it.
 */
void hv_drm_update_cursor(struct hv_drm_device *hv, bool shape)
{
	struct hv_drm_cursor *cursor = hv->cursor;
	int ret = 0;

	lockdep_assert_held(&cursor->lock);

	if (shape || cursor->shape_stale) {
		/*
		 * The host may still be waiting for the rest of a multi-part
		 * shape, and rejects new shapes until it gets a final part.
		 * A one pixel shape completes any such shape, and is a valid
		 * shape of its own otherwise.
		 */
		if (cursor->shape_stale)
			ret = hv_drm_send_ptr_shape(hv, 1, 1, 0, 0,
						    hv_drm_cursor_hidden_pixel);
		if (!ret)
			ret = hv_drm_send_ptr_shape(hv, cursor->width,
						    cursor->height,
						    cursor->hot_x,
						    cursor->hot_y,
						    cursor->image);
		cursor->shape_stale = ret;
	}

	hv_drm_send_ptr_position(hv, cursor->x, cursor->y);
}

void hv_drm_restore_cursor(struct hv_drm_device *hv)
{
	scoped_guard(mutex, &hv->cursor->lock)
		hv_drm_update_cursor(hv, true);
}

static void hv_drm_restore_cursor_work(struct work_struct *work)
{
	struct hv_drm_device *hv = container_of(work, struct hv_drm_device,
						cursor_work);

	hv_drm_restore_cursor(hv);
}

int hv_drm_cursor_init(struct hv_drm_device *hv)
{
	struct hv_drm_cursor *cursor;
	int ret;

	cursor = drmm_kzalloc(&hv->dev, sizeof(*cursor), GFP_KERNEL);
	if (!cursor)
		return -ENOMEM;

	ret = drmm_mutex_init(&hv->dev, &cursor->lock);
	if (ret)
		return ret;

	hv_drm_cursor_set_hidden(cursor);
	cursor->shape_stale = true;
	hv->cursor = cursor;

	INIT_WORK(&hv->cursor_work, hv_drm_restore_cursor_work);
	disable_work(&hv->cursor_work);

	return 0;
}

int hv_drm_update_dirt(struct hv_device *hdev, struct drm_rect *rect)
{
	struct hv_drm_device *hv = hv_get_drvdata(hdev);
	struct synthvid_msg msg;

	if (!hv->dirt_needed)
		return 0;

	memset(&msg, 0, sizeof(struct synthvid_msg));

	msg.vid_hdr.type = SYNTHVID_DIRT;
	msg.vid_hdr.size = sizeof(struct synthvid_msg_hdr) +
		sizeof(struct synthvid_dirt);
	msg.dirt.video_output = 0;
	msg.dirt.dirt_count = 1;
	msg.dirt.rect[0].x1 = rect->x1;
	msg.dirt.rect[0].y1 = rect->y1;
	msg.dirt.rect[0].x2 = rect->x2;
	msg.dirt.rect[0].y2 = rect->y2;

	hv_drm_sendpacket(hdev, &msg);

	return 0;
}

static int hv_drm_get_supported_resolution(struct hv_device *hdev)
{
	struct hv_drm_device *hv = hv_get_drvdata(hdev);
	struct synthvid_msg *msg = (struct synthvid_msg *)hv->init_buf;
	struct drm_device *dev = &hv->dev;
	unsigned long t;
	u8 index;
	int i;

	memset(msg, 0, sizeof(struct synthvid_msg));
	msg->vid_hdr.type = SYNTHVID_RESOLUTION_REQUEST;
	msg->vid_hdr.size = sizeof(struct synthvid_msg_hdr) +
		sizeof(struct synthvid_supported_resolution_req);
	msg->resolution_req.maximum_resolution_count =
		SYNTHVID_MAX_RESOLUTION_COUNT;
	hv_drm_sendpacket(hdev, msg);

	t = wait_for_completion_timeout(&hv->wait, VMBUS_VSP_TIMEOUT);
	if (!t) {
		drm_err(dev, "Time out on waiting resolution response\n");
		return -ETIMEDOUT;
	}

	if (msg->resolution_resp.resolution_count == 0 ||
	    msg->resolution_resp.resolution_count >
	    SYNTHVID_MAX_RESOLUTION_COUNT) {
		drm_err(dev, "Invalid resolution count: %d\n",
			msg->resolution_resp.resolution_count);
		return -ENODEV;
	}

	index = msg->resolution_resp.default_resolution_index;
	if (index >= msg->resolution_resp.resolution_count) {
		drm_err(dev, "Invalid resolution index: %d\n", index);
		return -ENODEV;
	}

	for (i = 0; i < msg->resolution_resp.resolution_count; i++) {
		hv->screen_width_max = max_t(u32, hv->screen_width_max,
			msg->resolution_resp.supported_resolution[i].width);
		hv->screen_height_max = max_t(u32, hv->screen_height_max,
			msg->resolution_resp.supported_resolution[i].height);
	}

	hv->preferred_width =
		msg->resolution_resp.supported_resolution[index].width;
	hv->preferred_height =
		msg->resolution_resp.supported_resolution[index].height;

	return 0;
}

static void hv_drm_receive_sub(struct hv_device *hdev, u32 bytes_recvd)
{
	struct hv_drm_device *hv = hv_get_drvdata(hdev);
	struct synthvid_msg *msg;
	size_t hdr_size;
	size_t need;

	if (!hv)
		return;

	hdr_size = sizeof(struct pipe_msg_hdr) +
		   sizeof(struct synthvid_msg_hdr);
	if (bytes_recvd < hdr_size) {
		drm_err_ratelimited(&hv->dev,
				    "synthvid packet too small for header: %u\n",
				    bytes_recvd);
		return;
	}

	msg = (struct synthvid_msg *)hv->recv_buf;
	need = hdr_size;

	switch (msg->vid_hdr.type) {
	case SYNTHVID_VERSION_RESPONSE:
		need += sizeof(struct synthvid_version_resp);
		break;
	case SYNTHVID_RESOLUTION_RESPONSE:
		/*
		 * The resolution response is variable length: the host
		 * fills resolution_count entries, not the full
		 * SYNTHVID_MAX_RESOLUTION_COUNT array. Require the fixed
		 * prefix first so resolution_count can be read, then
		 * demand exactly the count-sized array.
		 */
		need += offsetof(struct synthvid_supported_resolution_resp,
				 supported_resolution);
		if (bytes_recvd < need)
			break;
		if (msg->resolution_resp.resolution_count >
		    SYNTHVID_MAX_RESOLUTION_COUNT) {
			drm_err_ratelimited(&hv->dev,
					    "synthvid resolution count too large: %u\n",
					    msg->resolution_resp.resolution_count);
			return;
		}
		need += msg->resolution_resp.resolution_count *
			sizeof(struct hvd_screen_info);
		break;
	case SYNTHVID_VRAM_LOCATION_ACK:
		need += sizeof(struct synthvid_vram_location_ack);
		break;
	case SYNTHVID_FEATURE_CHANGE:
		/*
		 * Not a completion-driving message: validate its own payload
		 * and consume it here rather than falling through to the
		 * memcpy/complete shared by the wait-event responses.
		 */
		if (bytes_recvd < need +
		    sizeof(struct synthvid_feature_change)) {
			drm_err_ratelimited(&hv->dev,
					    "synthvid feature change packet too small: %u\n",
					    bytes_recvd);
			return;
		}
		hv->dirt_needed = msg->feature_chg.is_dirt_needed;
		/*
		 * Send the cursor to clients that may have just connected, from
		 * a work item, as that takes the cursor's mutex and the channel
		 * callback runs in atomic context.
		 */
		if (hv->dirt_needed)
			schedule_work(&hv->cursor_work);
		return;
	default:
		return;
	}

	/*
	 * Shared completion path for the wait-event responses
	 * (VERSION_RESPONSE, RESOLUTION_RESPONSE, VRAM_LOCATION_ACK):
	 * require the type-specific payload before handing the buffer to
	 * the waiter.
	 */
	if (bytes_recvd < need) {
		drm_err_ratelimited(&hv->dev,
				    "synthvid packet too small for type %u: %u < %zu\n",
				    msg->vid_hdr.type, bytes_recvd, need);
		return;
	}
	memcpy(hv->init_buf, msg, bytes_recvd);
	complete(&hv->wait);
}

static void hv_drm_receive(void *ctx)
{
	struct hv_device *hdev = ctx;
	struct hv_drm_device *hv = hv_get_drvdata(hdev);
	struct synthvid_msg *recv_buf;
	u32 bytes_recvd;
	u64 req_id;
	int ret;

	if (!hv)
		return;

	recv_buf = (struct synthvid_msg *)hv->recv_buf;

	do {
		ret = vmbus_recvpacket(hdev->channel, recv_buf,
				       VMBUS_MAX_PACKET_SIZE,
				       &bytes_recvd, &req_id);
		if (ret) {
			/*
			 * A nonzero return (e.g. -ENOBUFS for an oversized
			 * packet) is itself a malformed message: bytes_recvd
			 * then reports the required length rather than a copied
			 * payload, so it must not be forwarded to the
			 * sub-handler. Channel recovery is not attempted.
			 */
			drm_err_ratelimited(&hv->dev,
					    "vmbus_recvpacket failed: %d (need %u)\n",
					    ret, bytes_recvd);
		} else if (bytes_recvd > 0 &&
			   recv_buf->pipe_hdr.type == PIPE_MSG_DATA) {
			hv_drm_receive_sub(hdev, bytes_recvd);
		}
	} while (bytes_recvd > 0 && ret == 0);
}

int hv_drm_connect_vsp(struct hv_device *hdev)
{
	struct hv_drm_device *hv = hv_get_drvdata(hdev);
	struct drm_device *dev = &hv->dev;
	int ret;

	enable_work(&hv->cursor_work);
	ret = vmbus_open(hdev->channel, VMBUS_RING_BUFSIZE, VMBUS_RING_BUFSIZE,
			 NULL, 0, hv_drm_receive, hdev);
	if (ret) {
		disable_work_sync(&hv->cursor_work);
		drm_err(dev, "Unable to open vmbus channel\n");
		return ret;
	}

	/*
	 * Negotiate the protocol version with host. Since support for hosts
	 * older than WIN10 has been removed from Linux, only negotiate the
	 * WIN10 version.
	 */
	ret = hv_drm_negotiate_version(hdev, SYNTHVID_VERSION_WIN10);
	if (ret) {
		drm_err(dev, "Synthetic video device version not accepted %d\n", ret);
		goto error;
	}

	hv->screen_depth = SYNTHVID_DEPTH_WIN8;

	ret = hv_drm_get_supported_resolution(hdev);
	if (ret)
		drm_err(dev, "Failed to get supported resolution from host, use default\n");

	if (!hv->screen_width_max) {
		hv->screen_width_max = SYNTHVID_WIDTH_WIN8;
		hv->screen_height_max = SYNTHVID_HEIGHT_WIN8;
		hv->preferred_width = SYNTHVID_WIDTH_WIN8;
		hv->preferred_height = SYNTHVID_HEIGHT_WIN8;
	}

	hv->mmio_megabytes = hdev->channel->offermsg.offer.mmio_megabytes;

	return 0;

error:
	hv_drm_disconnect_vsp(hdev);
	return ret;
}

void hv_drm_disconnect_vsp(struct hv_device *hdev)
{
	struct hv_drm_device *hv = hv_get_drvdata(hdev);

	/* Stop the work before vmbus_close() frees the ring buffers */
	disable_work_sync(&hv->cursor_work);
	vmbus_close(hdev->channel);
}
