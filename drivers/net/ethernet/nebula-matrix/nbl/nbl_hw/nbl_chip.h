/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Nebula Matrix Limited.
 */

#ifndef _NBL_CHIP_H_
#define _NBL_CHIP_H_

#include "nbl_resource.h"
int nbl_res_chip_init_module(struct nbl_resource_mgt *res_mgt);
void nbl_res_chip_deinit_module(struct nbl_resource_mgt *res_mgt);
#endif
