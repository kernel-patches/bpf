/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Nebula Matrix Limited.
 */

#ifndef _NBL_INCLUDE_H_
#define _NBL_INCLUDE_H_

#include <linux/types.h>

/*  ------  Basic definitions  -------  */
#define NBL_DRIVER_NAME					"nbl"
#define NBL_MAX_PF					8
#define NBL_NEXT_ID(id, max) (((id) + 1) % ((max) + 1))

#define NBL_MAX_FUNC					520
#define NBL_MAX_ETHERNET				4

enum {
	NBL_VSI_DATA = 0,
};

struct nbl_func_caps {
	u32 has_ctrl:1;
	u32 has_net:1;
	u32 rsv:30;
};

struct nbl_init_param {
	struct nbl_func_caps caps;
};

#endif
