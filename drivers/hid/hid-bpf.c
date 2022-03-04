// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  BPF in HID support for Linux
 *
 *  Copyright (c) 2022 Benjamin Tissoires
 */

#include <linux/filter.h>
#include <linux/mutex.h>
#include <linux/slab.h>

#include <uapi/linux/bpf_hid.h>
#include <linux/hid.h>

static int __hid_bpf_match_sysfs(struct device *dev, const void *data)
{
	struct kernfs_node *kn = dev->kobj.sd;
	struct kernfs_node *uevent_kn;

	uevent_kn = kernfs_find_and_get_ns(kn, "uevent", NULL);

	return uevent_kn == data;
}

static struct hid_device *hid_bpf_fd_to_hdev(int fd)
{
	struct device *dev;
	struct hid_device *hdev;
	struct fd f = fdget(fd);
	struct inode *inode;
	struct kernfs_node *node;

	if (!f.file) {
		hdev = ERR_PTR(-EBADF);
		goto out;
	}

	inode = file_inode(f.file);
	node = inode->i_private;

	dev = bus_find_device(&hid_bus_type, NULL, node, __hid_bpf_match_sysfs);

	if (dev)
		hdev = to_hid_device(dev);
	else
		hdev = ERR_PTR(-EINVAL);

 out:
	fdput(f);
	return hdev;
}

static int hid_reconnect(struct hid_device *hdev)
{
	if (!test_and_set_bit(ffs(HID_STAT_REPROBED), &hdev->status))
		return device_reprobe(&hdev->dev);

	return 0;
}

static int hid_bpf_link_attach(struct hid_device *hdev, enum bpf_hid_attach_type type)
{
	int err = 0;

	switch (type) {
	case BPF_HID_ATTACH_DEVICE_EVENT:
		if (!hdev->bpf.ctx) {
			hdev->bpf.ctx = bpf_hid_allocate_ctx(hdev, HID_BPF_MAX_BUFFER_SIZE);
			if (IS_ERR(hdev->bpf.ctx)) {
				err = PTR_ERR(hdev->bpf.ctx);
				hdev->bpf.ctx = NULL;
			}
		}
		break;
	default:
		/* do nothing */
	}

	return err;
}

static void hid_bpf_link_attached(struct hid_device *hdev, enum bpf_hid_attach_type type)
{
	switch (type) {
	case BPF_HID_ATTACH_RDESC_FIXUP:
		hid_reconnect(hdev);
		break;
	default:
		/* do nothing */
	}
}

static void hid_bpf_array_detached(struct hid_device *hdev, enum bpf_hid_attach_type type)
{
	switch (type) {
	case BPF_HID_ATTACH_DEVICE_EVENT:
		kfree(hdev->bpf.ctx);
		hdev->bpf.ctx = NULL;
		break;
	case BPF_HID_ATTACH_RDESC_FIXUP:
		hid_reconnect(hdev);
		break;
	default:
		/* do nothing */
	}
}

int hid_bpf_get_data(struct hid_device *hdev, u8 *buf, size_t buf_size, u64 offset, u32 n,
		     u8 *data, u64 data_size)
{
	u32 *value = (u32 *)data;

	if (((offset + n) >> 3) >= buf_size)
		return -E2BIG;

	if (n <= 32) {
		/* data must be a pointer to a u32 */
		if (data_size != 4)
			return -EINVAL;

		*value = hid_field_extract(hdev, buf, offset, n);
		return 4;
	}

	/* if n > 32, use memcpy, but ensure we are dealing with full bytes */
	if ((n | offset) & 0x7)
		return -EINVAL;

	/* work on bytes now */
	offset = offset >> 3;
	n = n >> 3;

	if (n > data_size)
		return -EINVAL;

	memcpy(data, buf + offset, n);

	return n;
}

int hid_bpf_set_data(struct hid_device *hdev, u8 *buf, size_t buf_size, u64 offset, u32 n,
		     u8 *data, u64 data_size)
{
	u32 *value = (u32 *)data;

	if (((offset + n) >> 3) >= buf_size)
		return -E2BIG;

	if (n <= 32) {
		/* data must be a pointer to a u32 */
		if (data_size != 4)
			return -EINVAL;

		implement(hdev, buf, offset, n, *value);
		return 4;
	}

	/* if n > 32, use memcpy, but ensure we are dealing with full bytes */
	if ((n | offset) & 0x7)
		return -EINVAL;

	/* work on bytes now */
	offset = offset >> 3;
	n = n >> 3;

	if (n > data_size)
		return -EINVAL;

	memcpy(buf + offset, data, n);

	return n;
}

int hid_bpf_raw_request(struct hid_device *hdev, u8 *buf, size_t size,
			u8 rtype, u8 reqtype)
{
	struct hid_report *report;
	struct hid_report_enum *report_enum;
	u8 *dma_data;
	u32 report_len;
	int ret;

	/* check arguments */
	switch (rtype) {
	case HID_INPUT_REPORT:
	case HID_OUTPUT_REPORT:
	case HID_FEATURE_REPORT:
		break;
	default:
		return -EINVAL;
	}

	switch (reqtype) {
	case HID_REQ_GET_REPORT:
	case HID_REQ_GET_IDLE:
	case HID_REQ_GET_PROTOCOL:
	case HID_REQ_SET_REPORT:
	case HID_REQ_SET_IDLE:
	case HID_REQ_SET_PROTOCOL:
		break;
	default:
		return -EINVAL;
	}

	if (size < 1)
		return -EINVAL;

	report_enum = hdev->report_enum + rtype;
	report = hid_get_report(report_enum, buf);
	if (!report)
		return -EINVAL;

	report_len = hid_report_len(report);

	if (size > report_len)
		size = report_len;

	dma_data = kmemdup(buf, size, GFP_KERNEL);
	if (!dma_data)
		return -ENOMEM;

	ret = hid_hw_raw_request(hdev,
				 dma_data[0],
				 dma_data,
				 size,
				 rtype,
				 reqtype);

	if (ret > 0)
		memcpy(buf, dma_data, ret);

	kfree(dma_data);
	return ret;
}

static int hid_bpf_run_progs(struct hid_device *hdev, enum bpf_hid_attach_type type,
			     struct hid_bpf_ctx *ctx, u8 *data, int size)
{
	enum hid_bpf_event event = HID_BPF_UNDEF;

	if (type < 0 || !ctx)
		return -EINVAL;

	if (size > ctx->allocated_size)
		return -E2BIG;

	switch (type) {
	case BPF_HID_ATTACH_DEVICE_EVENT:
		event = HID_BPF_DEVICE_EVENT;
		break;
	case BPF_HID_ATTACH_RDESC_FIXUP:
		event = HID_BPF_RDESC_FIXUP;
		break;
	default:
		return -EINVAL;
	}

	if (!hdev->bpf.run_array[type])
		return 0;

	memset(ctx->data, 0, ctx->allocated_size);
	ctx->type = event;

	if (size && data) {
		memcpy(ctx->data, data, size);
		ctx->size = size;
	} else {
		ctx->size = 0;
	}

	return BPF_PROG_RUN_ARRAY(hdev->bpf.run_array[type], ctx, bpf_prog_run);
}

u8 *hid_bpf_raw_event(struct hid_device *hdev, u8 *data, int *size)
{
	int ret;

	if (bpf_hid_link_empty(&hdev->bpf, BPF_HID_ATTACH_DEVICE_EVENT))
		return data;

	ret = hid_bpf_run_progs(hdev, BPF_HID_ATTACH_DEVICE_EVENT,
				hdev->bpf.ctx, data, *size);
	if (ret)
		return ERR_PTR(ret);

	if (!hdev->bpf.ctx->size)
		return ERR_PTR(-EINVAL);

	*size = hdev->bpf.ctx->size;

	return hdev->bpf.ctx->data;
}

u8 *hid_bpf_report_fixup(struct hid_device *hdev, u8 *rdesc, unsigned int *size)
{
	struct hid_bpf_ctx *ctx = NULL;
	int ret;

	if (bpf_hid_link_empty(&hdev->bpf, BPF_HID_ATTACH_RDESC_FIXUP))
		goto ignore_bpf;

	ctx = bpf_hid_allocate_ctx(hdev, HID_MAX_DESCRIPTOR_SIZE);
	if (IS_ERR(ctx))
		goto ignore_bpf;

	ret = hid_bpf_run_progs(hdev, BPF_HID_ATTACH_RDESC_FIXUP, ctx, rdesc, *size);
	if (ret)
		goto ignore_bpf;

	*size = ctx->size;

	if (!*size) {
		rdesc = NULL;
		goto unlock;
	}

	rdesc = kmemdup(ctx->data, *size, GFP_KERNEL);

 unlock:
	kfree(ctx);
	return rdesc;

 ignore_bpf:
	kfree(ctx);
	return kmemdup(rdesc, *size, GFP_KERNEL);
}

int __init hid_bpf_module_init(void)
{
	struct bpf_hid_hooks hooks = {
		.hdev_from_fd = hid_bpf_fd_to_hdev,
		.link_attach = hid_bpf_link_attach,
		.link_attached = hid_bpf_link_attached,
		.array_detached = hid_bpf_array_detached,
		.hid_get_data = hid_bpf_get_data,
		.hid_set_data = hid_bpf_set_data,
		.hid_raw_request  = hid_bpf_raw_request,
	};

	bpf_hid_set_hooks(&hooks);

	return 0;
}

void __exit hid_bpf_module_exit(void)
{
	bpf_hid_set_hooks(NULL);
}
