// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021-2026, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/auxiliary_bus.h>
#include <linux/idr.h>

#include "adev.h"

static DEFINE_IDA(xsc_adev_ida);

static const char * const xsc_adev_name[] = {
	[XSC_ADEV_IDX_ETH] = XSC_ETH_ADEV_NAME,
};

static void xsc_release_adev(struct device *dev)
{
	struct xsc_adev *xsc_adev =
		container_of(dev, struct xsc_adev, adev.dev);

	kfree(xsc_adev);
}

static int xsc_adev_add(struct xsc_core_device *xdev, int idx)
{
	struct auxiliary_device	*adev;
	struct xsc_adev *xsc_adev;
	int ret;

	if (!xdev->xsc_adev_list)
		return -ENODEV;

	if (xdev->xsc_adev_list[idx])
		return 0;

	xsc_adev = kzalloc_obj(*xsc_adev, GFP_KERNEL);
	if (!xsc_adev)
		return -ENOMEM;

	adev = &xsc_adev->adev;
	adev->name = xsc_adev_name[idx];
	adev->id = xdev->adev_id;
	adev->dev.parent = &xdev->pdev->dev;
	adev->dev.release = xsc_release_adev;
	xsc_adev->xdev = xdev;

	ret = auxiliary_device_init(adev);
	if (ret) {
		kfree(xsc_adev);
		return ret;
	}

	ret = auxiliary_device_add(adev);
	if (ret) {
		auxiliary_device_uninit(adev);
		return ret;
	}

	xdev->xsc_adev_list[idx] = xsc_adev;

	return 0;
}

static void xsc_adev_del(struct xsc_core_device *xdev, int idx)
{
	struct xsc_adev *xsc_adev;
	struct auxiliary_device *adev;

	if (!xdev->xsc_adev_list)
		return;

	xsc_adev = xdev->xsc_adev_list[idx];
	if (!xsc_adev)
		return;

	/* Clear the slot before teardown: the driver's remove callback runs
	 * synchronously inside auxiliary_device_delete() and may re-enter
	 * xsc_adev_add() for this index.
	 */
	xdev->xsc_adev_list[idx] = NULL;

	adev = &xsc_adev->adev;
	auxiliary_device_delete(adev);
	auxiliary_device_uninit(adev);
}

int xsc_adev_init(struct xsc_core_device *xdev)
{
	struct xsc_adev **xsc_adev_list;
	int adev_id;
	int ret;

	xsc_adev_list = kcalloc(XSC_ADEV_IDX_MAX,
				sizeof(struct xsc_adev *),
				GFP_KERNEL);
	if (!xsc_adev_list)
		return -ENOMEM;
	xdev->xsc_adev_list = xsc_adev_list;

	adev_id = ida_alloc(&xsc_adev_ida, GFP_KERNEL);
	if (adev_id < 0) {
		ret = adev_id;
		goto err_free_adev_list;
	}
	xdev->adev_id = adev_id;

	ret = xsc_adev_add(xdev, XSC_ADEV_IDX_ETH);
	if (ret)
		goto err_dalloc_adev_id;

	return 0;

err_dalloc_adev_id:
	ida_free(&xsc_adev_ida, xdev->adev_id);
err_free_adev_list:
	kfree(xsc_adev_list);
	xdev->xsc_adev_list = NULL;

	return ret;
}

void xsc_adev_uninit(struct xsc_core_device *xdev)
{
	if (!xdev->xsc_adev_list)
		return;

	xsc_adev_del(xdev, XSC_ADEV_IDX_ETH);
	ida_free(&xsc_adev_ida, xdev->adev_id);
	kfree(xdev->xsc_adev_list);
	xdev->xsc_adev_list = NULL;
}
