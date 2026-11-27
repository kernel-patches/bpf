/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2023 Intel Corporation
 */

#ifndef _XE_VRAM_CONFIG_H_
#define _XE_VRAM_CONFIG_H_

struct xe_tile;

int xe_vram_config_sysfs_init(struct xe_tile *tile);

#endif /* _XE_VRAM_CONFIG_H_ */
