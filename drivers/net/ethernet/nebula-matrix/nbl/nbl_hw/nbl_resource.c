// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Nebula Matrix Limited.
 */

#include <linux/pci.h>
#include "nbl_resource.h"

int nbl_res_func_id_to_vsi_id(struct nbl_resource_mgt *res_mgt, u16 func_id,
			      u16 type, u16 *vsi_id)
{
	struct nbl_vsi_info *vsi_info = res_mgt->resource_info->vsi_info;
	enum nbl_vsi_serv_type dst_type = NBL_VSI_SERV_PF_DATA_TYPE;
	struct nbl_common_info *common = res_mgt->common;
	struct device *dev = res_mgt->common->dev;
	int pfid = func_id;
	u32 rel_pf_id;
	int ret;

	if (!common->has_ctrl || !vsi_id) {
		dev_dbg(dev, "No control plane or null vsi output ptr\n");
		return -EINVAL;
	}
	ret = nbl_common_func_id_to_rel_pf_id(common, pfid, &rel_pf_id);
	if (ret)
		return ret;
	if (rel_pf_id >= vsi_info->num) {
		dev_err(dev, "PF %d (diff=%u) exceeds vsi_info->num (%u)\n",
			pfid, rel_pf_id, vsi_info->num);
		return -EINVAL;
	}

	ret = nbl_res_pf_dev_vsi_type_to_hw_vsi_type(res_mgt, type, &dst_type);
	if (ret) {
		dev_err(dev, "Invalid vsi type %u func_id %u\n", type, func_id);
		return ret;
	}
	*vsi_id = vsi_info->serv_info[rel_pf_id][dst_type].base_id;
	return 0;
}

int nbl_res_vsi_id_to_pf_id(struct nbl_resource_mgt *res_mgt, u16 vsi_id)
{
	struct nbl_vsi_info *vsi_info = res_mgt->resource_info->vsi_info;
	struct nbl_common_info *common = res_mgt->common;
	struct device *dev = res_mgt->common->dev;
	int j = NBL_VSI_SERV_PF_DATA_TYPE;
	int pf_id, i;

	if (!common->has_ctrl) {
		dev_dbg(dev, "No control plane available\n");
		return -EINVAL;
	}
	for (i = 0; i < vsi_info->num; i++) {
		if (vsi_id >= vsi_info->serv_info[i][j].base_id &&
		    (vsi_id < vsi_info->serv_info[i][j].base_id +
					vsi_info->serv_info[i][j].num)) {
			pf_id = i + common->mgt_pf;
			if (pf_id >= NBL_MAX_PF) {
				dev_err(dev, "PF ID overflow\n");
				return -ERANGE;
			}
			return pf_id;
		}
	}

	dev_dbg(dev, "VSI ID %u not found\n", vsi_id);
	return -ENOENT;
}

int nbl_res_func_id_to_bdf(struct nbl_resource_mgt *res_mgt, u16 func_id,
			   u8 *bus, u8 *dev, u8 *function)
{
	struct nbl_common_info *common = res_mgt->common;
	struct nbl_sriov_info *sriov_info;
	int pfid = func_id;
	u8 pf_bus, devfn;
	u32 rel_pf_id;
	int ret;

	if (!common->has_ctrl || !bus || !dev || !function)
		return -EINVAL;
	ret = nbl_common_func_id_to_rel_pf_id(common, pfid, &rel_pf_id);
	if (ret)
		return ret;
	if (rel_pf_id >= common->max_pf) {
		dev_err(common->dev,
			"func_id=%u rel_pf_id=%u exceeds max_pf=%u, VF BDF unsupported\n",
			pfid, rel_pf_id,
			common->max_pf);
		return -EOPNOTSUPP;
	}
	sriov_info = res_mgt->resource_info->sriov_info + rel_pf_id;
	pf_bus = PCI_BUS_NUM(sriov_info->bdf);
	devfn = sriov_info->bdf & 0xff;
	*bus = pf_bus;
	*dev = PCI_SLOT(devfn);
	*function = PCI_FUNC(devfn);

	return 0;
}

int nbl_res_get_eth_id(struct nbl_resource_mgt *res_mgt, u16 func_id,
		       u16 vsi_id, u8 *eth_num, u8 *eth_id, u8 *logic_eth_id)
{
	struct nbl_eth_info *eth_info = res_mgt->resource_info->eth_info;
	struct nbl_common_info *common = res_mgt->common;
	struct device *dev = res_mgt->common->dev;
	int pfid = func_id;
	int rel_pf_id;
	int abs_pf_id;

	if (!common->has_ctrl || !eth_num || !eth_id || !logic_eth_id)
		return -EINVAL;
	abs_pf_id = nbl_res_vsi_id_to_pf_id(res_mgt, vsi_id);
	if (abs_pf_id < 0) {
		dev_err(dev, "Failed to get PF ID from VSI ID %u\n", vsi_id);
		return -EINVAL;
	}
	if (abs_pf_id != pfid) {
		dev_err(dev, "func_id %u does not match pf derived from vsi_id %u\n",
			pfid, vsi_id);
		return -EINVAL;
	}
	rel_pf_id = abs_pf_id - common->mgt_pf;

	if (rel_pf_id >= eth_info->eth_num) {
		dev_err(dev, "rel_pf_id %d out of range [0, %u)\n",
			rel_pf_id, eth_info->eth_num);
		return -ERANGE;
	}

	*eth_num = eth_info->eth_num;
	*eth_id = eth_info->eth_id[rel_pf_id];
	*logic_eth_id = rel_pf_id;
	return 0;
}

int nbl_res_pf_dev_vsi_type_to_hw_vsi_type(struct nbl_resource_mgt *res_mgt,
					   u16 src_type,
					   enum nbl_vsi_serv_type *dst_type)
{
	switch (src_type) {
	case NBL_VSI_DATA:
		*dst_type = NBL_VSI_SERV_PF_DATA_TYPE;
		return 0;
	default:
		dev_err_once(res_mgt->common->dev,
			     "Unsupported vsi src_type %u\n", src_type);
		return -EINVAL;
	}
}
