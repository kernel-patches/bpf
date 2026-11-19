/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Nebula Matrix Limited.
 */

#ifndef _NBL_DEF_DEV_H_
#define _NBL_DEF_DEV_H_

struct nbl_adapter;

int nbl_dev_init(struct nbl_adapter *adapter);
void nbl_dev_remove(struct nbl_adapter *adapter);

#endif
