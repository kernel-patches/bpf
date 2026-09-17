/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2026, Intel Corporation. */

#ifndef _ICE_ACL_MAIN_H_
#define _ICE_ACL_MAIN_H_
#include "ice.h"
#include <linux/ethtool.h>
int ice_acl_add_rule_ethtool(struct ice_vsi *vsi, struct ethtool_rxnfc *cmd);
#endif /* _ICE_ACL_MAIN_H_ */
