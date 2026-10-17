/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Nebula Matrix Limited.
 */

#ifndef _NBL_DEV_H_
#define _NBL_DEV_H_

#include <linux/types.h>

#include "../nbl_include/nbl_include.h"
#include "../nbl_include/nbl_def_channel.h"
#include "../nbl_include/nbl_def_hw.h"
#include "../nbl_include/nbl_def_resource.h"
#include "../nbl_include/nbl_def_dispatch.h"
#include "../nbl_include/nbl_def_dev.h"
#include "../nbl_include/nbl_def_common.h"
#include "../nbl_core.h"

#define NBL_STRING_NAME_LEN			32

enum nbl_msix_serv_type {
	NBL_MSIX_NET_TYPE,
	NBL_MSIX_MAILBOX_TYPE,
	NBL_MSIX_TYPE_MAX
};

struct nbl_msix_serv_info {
	char irq_name[NBL_STRING_NAME_LEN];
	u16 num;
	u16 base_vector_id;
	/* true: hw report msix, hw need to mask actively */
	bool hw_self_mask_en;
};

struct nbl_msix_info {
	struct nbl_msix_serv_info serv_info[NBL_MSIX_TYPE_MAX];
};

struct nbl_dev_common {
	struct nbl_dev_mgt *dev_mgt;
	struct nbl_msix_info msix_info;
	char mailbox_name[NBL_STRING_NAME_LEN];
	/* for ctrl-dev/net-dev mailbox recv msg */
	struct work_struct clean_mbx_task;
};

struct nbl_dev_mgt {
	struct nbl_common_info *common;
	struct nbl_dispatch_ops_tbl *disp_ops_tbl;
	struct nbl_channel_ops_tbl *chan_ops_tbl;
	struct nbl_dev_common *common_dev;
};

#endif
