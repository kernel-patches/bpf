/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Nebula Matrix Limited.
 */

#ifndef _NBL_DEF_RESOURCE_H_
#define _NBL_DEF_RESOURCE_H_

#include <linux/types.h>

struct nbl_resource_mgt;
struct nbl_adapter;

int nbl_res_init_leonis(struct nbl_adapter *adapter);
void nbl_res_remove_leonis(struct nbl_adapter *adapter);
#endif
