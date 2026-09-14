/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (c) 2022, MediaTek Inc.
 */

#ifndef __MTK_UTILITY_H__
#define __MTK_UTILITY_H__

#include <linux/device.h>
#include "mtk_dev.h"

#define MTK_UEVENT_INFO_LEN 128

/* MTK uevent */
enum mtk_uevent_id {
	MTK_UEVENT_UNDEF = 0,
	MTK_UEVENT_FSM = 1,
	MTK_UEVENT_MINIDUMP = 2,
	MTK_UEVENT_LOWPOWER = 3,
	MTK_UEVENT_MAX
};

static inline void mtk_uevent_notify(struct device *dev, enum mtk_uevent_id id, const char *info)
{
	char buf[MTK_UEVENT_INFO_LEN];
	char *ext[2] = {NULL, NULL};

	snprintf(buf, MTK_UEVENT_INFO_LEN, "%s:event_id=%d, info=%s",
		 dev->kobj.name, id, info);
	ext[0] = buf;
	kobject_uevent_env(&dev->kobj, KOBJ_CHANGE, ext);
}
#endif /* __MTK_UTILITY_H__ */
