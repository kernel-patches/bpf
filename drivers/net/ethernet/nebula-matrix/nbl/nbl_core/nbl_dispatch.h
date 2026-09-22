/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Nebula Matrix Limited.
 */

#ifndef _NBL_DISPATCH_H_
#define _NBL_DISPATCH_H_
#include "../nbl_include/nbl_include.h"
#include "../nbl_include/nbl_def_channel.h"
#include "../nbl_include/nbl_def_resource.h"
#include "../nbl_include/nbl_def_dispatch.h"
#include "../nbl_include/nbl_def_common.h"
#include "../nbl_core.h"

struct nbl_dispatch_mgt {
	struct nbl_common_info *common;
	struct nbl_resource_ops_tbl *res_ops_tbl;
	struct nbl_channel_ops_tbl *chan_ops_tbl;
	struct nbl_dispatch_ops_tbl *disp_ops_tbl;
	DECLARE_BITMAP(ctrl_lvl, NBL_DISP_CTRL_LVL_MAX);
};

#endif
