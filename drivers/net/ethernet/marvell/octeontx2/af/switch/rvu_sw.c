// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2026 Marvell.
 *
 */

#include <linux/bitfield.h>
#include "rvu.h"
#include "rvu_sw.h"

u32 rvu_sw_port_id(struct rvu *rvu, u16 pcifunc)
{
	u32 port_id;
	u16 rep_id;

	rep_id  = rvu_rep_get_vlan_id(rvu, pcifunc);

	port_id = FIELD_PREP(GENMASK_ULL(31, 16), rep_id) |
		  FIELD_PREP(GENMASK_ULL(15, 0), pcifunc);

	return port_id;
}

int rvu_mbox_handler_swdev2af_notify(struct rvu *rvu,
				     struct swdev2af_notify_req *req,
				     struct msg_rsp *rsp)
{
	return 0;
}
