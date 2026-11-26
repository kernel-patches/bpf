// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2026, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "common/xsc_core.h"
#include "common/xsc_cmd.h"

int xsc_core_query_vport_state(struct xsc_core_device *xdev, u16 vport,
			       u8 *state)
{
	struct xsc_query_vport_state_out out;
	struct xsc_query_vport_state_in in;
	u32 val = 0;
	int err;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_VPORT_STATE);
	val |= FIELD_PREP(XSC_QUERY_VPORT_VPORT_NUM_MASK, vport);
	if (vport)
		val |= XSC_QUERY_VPORT_OTHER_VPORT;
	in.data0 = cpu_to_be32(val);

	err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (err) {
		pci_err(xdev->pdev, "failed to query vport state, err=%d, status=%d\n",
			err, out.hdr.status);
		return err;
	}

	*state = FIELD_GET(XSC_QUERY_VPORT_STATE_MASK, out.state);
	return 0;
}
EXPORT_SYMBOL_GPL(xsc_core_query_vport_state);
