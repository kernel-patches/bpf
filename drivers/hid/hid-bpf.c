// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  BPF in HID support for Linux
 *
 *  Copyright (c) 2021 Benjamin Tissoires
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

static struct hid_bpf_ctx *hid_bpf_allocate_ctx(struct hid_device *hdev)
{
	struct hid_bpf_ctx *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	ctx->hdev = hdev;

	return ctx;
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
			hdev->bpf.ctx = hid_bpf_allocate_ctx(hdev);
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

int hid_bpf_get_data(struct hid_device *hdev, u8 *buf, u64 offset, u8 n)
{
	if (n > 32 ||
	    ((offset + n) >> 3) >= HID_BPF_MAX_BUFFER_SIZE)
		return 0;

	return hid_field_extract(hdev, buf, offset, n);
}

int hid_bpf_set_data(struct hid_device *hdev, u8 *buf, u64 offset, u8 n, u32 data)
{
	if (n > 32 ||
	    ((offset + n) >> 3) >= HID_BPF_MAX_BUFFER_SIZE)
		return -EINVAL;

	implement(hdev, buf, offset, n, data);

	return 0;
}

static int hid_bpf_run_progs(struct hid_device *hdev, enum bpf_hid_attach_type type,
			     struct hid_bpf_ctx *ctx, u8 *data, int size)
{
	enum hid_bpf_event event = HID_BPF_UNDEF;

	if (type < 0 || !ctx)
		return -EINVAL;

	switch (type) {
	case BPF_HID_ATTACH_DEVICE_EVENT:
		event = HID_BPF_DEVICE_EVENT;
		if (size > sizeof(ctx->u.device.data))
			return -E2BIG;
		break;
	case BPF_HID_ATTACH_RDESC_FIXUP:
		event = HID_BPF_RDESC_FIXUP;
		if (size > sizeof(ctx->u.rdesc.data))
			return -E2BIG;
		break;
	default:
		return -EINVAL;
	}

	if (!hdev->bpf.run_array[type])
		return 0;

	memset(ctx, 0, sizeof(*ctx));
	ctx->hdev = hdev;
	ctx->type = event;

	if (size && data) {
		switch (event) {
		case HID_BPF_DEVICE_EVENT:
			memcpy(ctx->u.device.data, data, size);
			ctx->u.device.size = size;
			break;
		case HID_BPF_RDESC_FIXUP:
			memcpy(ctx->u.rdesc.data, data, size);
			ctx->u.device.size = size;
			break;
		default:
			/* do nothing */
		}
	}

	BPF_PROG_RUN_ARRAY(hdev->bpf.run_array[type], ctx, bpf_prog_run);

	return 0;
}

u8 *hid_bpf_raw_event(struct hid_device *hdev, u8 *data, int *size)
{
	int ret;

	if (bpf_hid_link_empty(&hdev->bpf, BPF_HID_ATTACH_DEVICE_EVENT))
		return data;

	ret = hid_bpf_run_progs(hdev, BPF_HID_ATTACH_DEVICE_EVENT,
				hdev->bpf.ctx, data, *size);
	if (ret)
		return data;

	if (!hdev->bpf.ctx->u.device.size)
		return ERR_PTR(-EINVAL);

	*size = hdev->bpf.ctx->u.device.size;

	return hdev->bpf.ctx->u.device.data;
}

u8 *hid_bpf_report_fixup(struct hid_device *hdev, u8 *rdesc, unsigned int *size)
{
	struct hid_bpf_ctx *ctx = NULL;
	int ret;

	if (bpf_hid_link_empty(&hdev->bpf, BPF_HID_ATTACH_RDESC_FIXUP))
		goto ignore_bpf;

	ctx = hid_bpf_allocate_ctx(hdev);
	if (IS_ERR(ctx))
		goto ignore_bpf;

	ret = hid_bpf_run_progs(hdev, BPF_HID_ATTACH_RDESC_FIXUP, ctx, rdesc, *size);
	if (ret)
		goto ignore_bpf;

	*size = ctx->u.rdesc.size;

	if (!*size) {
		rdesc = NULL;
		goto unlock;
	}

	rdesc = kmemdup(ctx->u.rdesc.data, *size, GFP_KERNEL);

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
	};

	bpf_hid_set_hooks(&hooks);

	return 0;
}

void __exit hid_bpf_module_exit(void)
{
	bpf_hid_set_hooks(NULL);
}
