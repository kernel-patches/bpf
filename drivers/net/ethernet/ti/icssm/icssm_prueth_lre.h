/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020 Texas Instruments Incorporated - http://www.ti.com
 */

#ifndef __NET_TI_PRUETH_LRE_H
#define __NET_TI_PRUETH_LRE_H

#include <linux/etherdevice.h>
#include <linux/interrupt.h>
#include <linux/if_vlan.h>

#include "icssm_prueth.h"
#include "icssm_lre_firmware.h"

void icssm_prueth_lre_config(struct prueth *prueth);
void icssm_prueth_lre_cleanup(struct prueth *prueth);
void icssm_prueth_lre_config_check_flags(struct prueth *prueth);

#endif /* __NET_TI_PRUETH_LRE_H */
