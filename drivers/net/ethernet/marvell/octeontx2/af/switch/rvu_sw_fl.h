/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2026 Marvell.
 *
 */

#ifndef RVU_SW_FL_H
#define RVU_SW_FL_H
int rvu_sw_fl_stats_sync2db(struct rvu *rvu, struct fl_info *fl, int cnt);
void rvu_sw_fl_shutdown(void);

#endif
