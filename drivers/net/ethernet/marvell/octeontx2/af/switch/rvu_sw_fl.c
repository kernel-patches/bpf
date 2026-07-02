// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2026 Marvell.
 *
 */
#include "rvu.h"

int rvu_mbox_handler_fl_get_stats(struct rvu *rvu,
				  struct fl_get_stats_req *req,
				  struct fl_get_stats_rsp *rsp)
{
	return 0;
}

int rvu_mbox_handler_fl_notify(struct rvu *rvu,
			       struct fl_notify_req *req,
			       struct msg_rsp *rsp)
{
	return 0;
}
