// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Nebula Matrix Limited.
 */
#include <linux/device.h>
#include <linux/pci.h>
#include <linux/bits.h>
#include "nbl_resource_leonis.h"

static struct nbl_resource_ops res_ops = {
	.get_vsi_id = nbl_res_func_id_to_vsi_id,
	.get_eth_id = nbl_res_get_eth_id,
};

static struct nbl_resource_mgt *
nbl_res_setup_res_mgt(struct nbl_common_info *common)
{
	struct nbl_resource_info *resource_info;
	struct nbl_resource_mgt *res_mgt;
	struct device *dev = common->dev;

	res_mgt = devm_kzalloc(dev, sizeof(*res_mgt), GFP_KERNEL);
	if (!res_mgt)
		return ERR_PTR(-ENOMEM);
	res_mgt->common = common;

	resource_info =
		devm_kzalloc(dev, sizeof(*resource_info), GFP_KERNEL);
	if (!resource_info)
		return ERR_PTR(-ENOMEM);
	res_mgt->resource_info = resource_info;

	return res_mgt;
}

static struct nbl_resource_ops_tbl *
nbl_res_setup_ops(struct device *dev, struct nbl_resource_mgt *res_mgt)
{
	struct nbl_resource_ops_tbl *res_ops_tbl;

	res_ops_tbl = devm_kzalloc(dev, sizeof(*res_ops_tbl), GFP_KERNEL);
	if (!res_ops_tbl)
		return ERR_PTR(-ENOMEM);
	if (!res_ops.get_vsi_id || !res_ops.get_eth_id)
		return ERR_PTR(-EINVAL);
	res_ops_tbl->ops = &res_ops;
	res_ops_tbl->priv = res_mgt;

	return res_ops_tbl;
}

static int nbl_res_ctrl_dev_setup_eth_info(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_hw_ops *hw_ops = res_mgt->hw_ops_tbl->ops;
	struct device *dev = res_mgt->common->dev;
	struct nbl_eth_info *eth_info;
	u32 eth_bitmap = 0, eth_id;
	u32 eth_num = 0;
	u32 fw_port_num;
	int i;

	eth_info = devm_kzalloc(dev, sizeof(*eth_info), GFP_KERNEL);
	if (!eth_info)
		return -ENOMEM;

	res_mgt->resource_info->eth_info = eth_info;

	fw_port_num = res_mgt->resource_info->board_info.eth_num;

	hw_ops->get_fw_eth_map(res_mgt->hw_ops_tbl->priv, &eth_bitmap);
	if (eth_bitmap & ~((1 << NBL_MAX_ETHERNET) - 1)) {
		dev_err(dev, "FW reported invalid eth_bitmap 0x%x\n",
			eth_bitmap);
		return -EINVAL;
	}
	if (fw_port_num != hweight32(eth_bitmap)) {
		dev_err(dev, "FW inconsistency: port_num=%u, bitmap=0x%x\n",
			fw_port_num, eth_bitmap);
		return -EINVAL;
	}
	/*
	 * Firmware is ready before probe. Valid port counts are 1/2/4;
	 * 0 (invalid config), 3 (unsupported topology), and >4 (exceeds
	 * hardware max) are all rejected with -EINVAL.
	 */
	if (fw_port_num == 0 || fw_port_num == 3 ||
	    fw_port_num > NBL_MAX_ETHERNET) {
		dev_err(dev, "FW reports %u Ethernet ports, unsupported (valid: 1/2/4)\n",
			fw_port_num);
		return -EINVAL;
	}
	eth_info->eth_num = fw_port_num;
	/* Intentional design constraint: each PF maps to exactly one
	 * Ethernet port. This couples PF identity to port identity
	 * and is required by nbl_res_get_eth_id() which indexes
	 * eth_info->eth_id[] by relative PF id.
	 */
	if (res_mgt->common->max_pf != eth_info->eth_num) {
		dev_err(dev, "Invalid PF-to-port topology: max_pf=%u, eth_num=%u\n",
			res_mgt->common->max_pf, eth_info->eth_num);
		return -EINVAL;
	}

	/*
	 * Any subset of valid bitmap bits is accepted (e.g. 0/1, 0/2,
	 * 1/3, etc.).  Firmware only needs to report the correct count
	 * of active ports; no hard-coded fixed bit positions required.
	 */
	for (i = 0; i < NBL_MAX_ETHERNET; i++) {
		if ((1 << i) & eth_bitmap) {
			set_bit(i, eth_info->eth_bitmap);
			eth_info->eth_id[eth_num] = i;
			eth_info->logic_eth_id[i] = eth_num;
			eth_num++;
		}
	}

	for (i = 0; i < res_mgt->common->max_pf; i++) {
		eth_id = eth_info->eth_id[i];
		eth_info->pf_bitmap[eth_id] |= BIT(i);
	}

	return 0;
}

static int nbl_res_ctrl_dev_sriov_info_init(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_hw_ops *hw_ops = res_mgt->hw_ops_tbl->ops;
	struct nbl_hw_mgt *p = res_mgt->hw_ops_tbl->priv;
	struct nbl_common_info *common = res_mgt->common;
	struct nbl_sriov_info *sriov_info;
	struct device *dev = common->dev;
	u8 hw_bus = 0;
	u16 function;
	u16 func_id;

	hw_ops->get_real_bus(p, &hw_bus);
	if (common->function + common->max_pf > NBL_MAX_PF) {
		dev_err(dev, "PF count exceeds available function space\n");
		return -EINVAL;
	}
	sriov_info = devm_kcalloc(dev, common->max_pf,
				  sizeof(*sriov_info), GFP_KERNEL);
	if (!sriov_info)
		return -ENOMEM;

	res_mgt->resource_info->sriov_info = sriov_info;
	/*
	 * common->hw_bus supplies bus number for channel mailbox QINFO mapping.
	 * Execution order guarantee: this assignment runs before
	 * cfg_chan_qinfo_map_table(), only executed
	 * on control PF path.
	 */
	common->hw_bus = hw_bus;

	for (func_id = 0; func_id < common->max_pf; func_id++) {
		sriov_info = res_mgt->resource_info->sriov_info + func_id;
		function = common->function + func_id;
		sriov_info->bdf = PCI_DEVID(common->hw_bus,
					    PCI_DEVFN(common->devid, function));
	}

	return 0;
}

static int nbl_res_ctrl_dev_vsi_info_init(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_eth_info *eth_info = res_mgt->resource_info->eth_info;
	struct nbl_common_info *common = res_mgt->common;
	struct device *dev = common->dev;
	struct nbl_vsi_info *vsi_info;
	int i;

	vsi_info = devm_kzalloc(dev, sizeof(*vsi_info), GFP_KERNEL);
	if (!vsi_info)
		return -ENOMEM;

	res_mgt->resource_info->vsi_info = vsi_info;
	/*
	 * case 1 one port(1pf)
	 * pf0 (NBL_VSI_SERV_PF_DATA_TYPE) vsi is 0
	 * case 2 two port(2pf)
	 * pf0,pf1(NBL_VSI_SERV_PF_DATA_TYPE) vsi is 0,512
	 * case 3 four port(4pf)
	 * pf0,pf1,pf2,pf3(NBL_VSI_SERV_PF_DATA_TYPE) vsi is 0,256,512,768
	 */

	vsi_info->num = eth_info->eth_num;
	/*
	 * eth_num can be 1/2/4:
	 * - 2/4 ports use dedicated gap constants;
	 * - 1 port falls back to NBL_DEFAULT_VSI_ID_GAP (1024).
	 * All three values produce valid base_id offsets.
	 */
	for (i = 0; i < vsi_info->num; i++) {
		vsi_info->serv_info[i][NBL_VSI_SERV_PF_DATA_TYPE].base_id =
			i * nbl_vsi_id_gap(vsi_info->num);
		vsi_info->serv_info[i][NBL_VSI_SERV_PF_DATA_TYPE].num = 1;
	}

	return 0;
}

static int nbl_res_init_pf_num(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_hw_ops *hw_ops = res_mgt->hw_ops_tbl->ops;
	u32 exp_contiguous_mask = 0;
	u32 pf_mask = 0;
	u32 pf_num = 0;
	int i;

	hw_ops->get_host_pf_mask(res_mgt->hw_ops_tbl->priv, &pf_mask);

	/*
	 * k_pf_mask register rule:
	 * bit N == 0  -> PF#N enabled; bit N == 1 -> PF#N masked out.
	 * Hardware constraint: bit0 is PF0's mask bit; driver requires
	 * PF0 enabled as management PF, so bit0 must be clear.
	 * All-zero pf_mask means all PF0~PF7 are enabled, which is unsupported
	 * by the driver
	 *
	 * Product firmware constraint: only 3 valid configurations supported:
	 * 1 PF  (PF0 only): pf_num = 1, mask = 0xfe
	 * 2 PFs (PF0,PF1):  pf_num = 2, mask = 0xfc
	 * 4 PFs (PF0~PF3): pf_num = 4, mask = 0xf0
	 * No other PF count or sparse/non-contiguous PF layout is allowed.
	 */
	for (i = 0; i < NBL_MAX_PF; i++) {
		if (!(pf_mask & (1 << i)))
			pf_num++;
	}

	/*
	 * Sanity check: enabled PFs must be contiguous starting from PF0.
	 * Current resource framework uses relative PF id, sparse PF layout
	 * will cause mismatch between resource layer and hardware func_id.
	 */
	for (i = 0; i < pf_num; i++)
		exp_contiguous_mask |= BIT(i);
	if ((pf_mask & exp_contiguous_mask) != 0) {
		dev_err(res_mgt->common->dev,
			"pf_mask 0x%08x: non-contiguous enabled PF, unsupported\n",
			pf_mask);
		return -EINVAL;
	}

	/* Only allow product-specified PF count: 1 / 2 / 4 */
	if (pf_num != 1 && pf_num != 2 && pf_num != 4) {
		dev_err(res_mgt->common->dev,
			"Invalid pf_num=%u (mask=0x%08x), only 1/2/4 PFs supported\n",
			pf_num, pf_mask);
		return -EINVAL;
	}

	res_mgt->common->max_pf = pf_num;

	return 0;
}

static void nbl_res_init_board_info(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_hw_ops *hw_ops = res_mgt->hw_ops_tbl->ops;

	hw_ops->get_board_info(res_mgt->hw_ops_tbl->priv,
			       &res_mgt->resource_info->board_info);
}

static int nbl_res_start(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_common_info *common = res_mgt->common;
	int ret = 0;

	if (common->has_ctrl) {
		nbl_res_init_board_info(res_mgt);

		ret = nbl_res_init_pf_num(res_mgt);
		if (ret)
			return ret;

		ret = nbl_res_ctrl_dev_sriov_info_init(res_mgt);
		if (ret)
			return ret;

		ret = nbl_res_ctrl_dev_setup_eth_info(res_mgt);
		if (ret)
			return ret;

		ret = nbl_res_ctrl_dev_vsi_info_init(res_mgt);
		if (ret)
			return ret;
	}

	return 0;
}

int nbl_res_init_leonis(struct nbl_adapter *adap)
{
	struct nbl_channel_ops_tbl *chan_ops_tbl = adap->intf.channel_ops_tbl;
	struct nbl_hw_ops_tbl *hw_ops_tbl = adap->intf.hw_ops_tbl;
	struct nbl_common_info *common = &adap->common;
	struct nbl_resource_ops_tbl *res_ops_tbl;
	struct device *dev = &adap->pdev->dev;
	struct nbl_resource_mgt *res_mgt;
	int ret;

	res_mgt = nbl_res_setup_res_mgt(common);
	if (IS_ERR(res_mgt)) {
		ret = PTR_ERR(res_mgt);
		return ret;
	}
	res_mgt->chan_ops_tbl = chan_ops_tbl;
	res_mgt->hw_ops_tbl = hw_ops_tbl;

	ret = nbl_res_start(res_mgt);
	if (ret)
		return ret;

	res_ops_tbl = nbl_res_setup_ops(dev, res_mgt);
	if (IS_ERR(res_ops_tbl)) {
		ret = PTR_ERR(res_ops_tbl);
		return ret;
	}
	adap->intf.resource_ops_tbl = res_ops_tbl;
	adap->core.res_mgt = res_mgt;

	return 0;
}

void nbl_res_remove_leonis(struct nbl_adapter *adap)
{
	/*
	 * No resource release here because all memory uses devm managed
	 * allocation
	 */
}
