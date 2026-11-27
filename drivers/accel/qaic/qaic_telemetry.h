/* SPDX-License-Identifier: GPL-2.0-only */

/* Copyright (c) 2020, The Linux Foundation. All rights reserved. */

#ifndef __QAIC_TELEMETRY_H__
#define __QAIC_TELEMETRY_H__

#include "qaic.h"

int qaic_telemetry_register(void);
void qaic_telemetry_unregister(void);
void wake_all_telemetry(struct qaic_device *qdev);

#endif /* __QAIC_TELEMETRY_H__ */
