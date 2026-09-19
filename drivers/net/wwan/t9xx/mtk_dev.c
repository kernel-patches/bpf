// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022, MediaTek Inc.
 */

#include <linux/module.h>

#include "mtk_dev.h"
#include "mtk_port.h"
#include "mtk_port_io.h"

static int __init mtk_common_drv_init(void)
{
	int ret;

	ret = mtk_port_io_init();
	if (ret)
		goto err_init_devid;

err_init_devid:
	return ret;
}
module_init(mtk_common_drv_init);

static void __exit mtk_common_drv_exit(void)
{
	mtk_port_io_exit();
	mtk_port_stale_list_grp_cleanup();
}
module_exit(mtk_common_drv_exit);

MODULE_DESCRIPTION("MediaTek T9xx PCIe WWAN driver");
MODULE_LICENSE("GPL");
