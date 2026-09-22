// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Nebula Matrix Limited.
 */
#include <linux/device.h>
#include <linux/pci.h>
#include <linux/bits.h>
#include <linux/io.h>
#include <linux/spinlock.h>
#include <linux/bitfield.h>
#include "nbl_hw_leonis.h"

static void nbl_hw_read_mbx_regs(struct nbl_hw_mgt *hw_mgt, u64 reg, u32 *data,
				 u32 len)
{
	u32 i;

	if (len % 4)
		return;
	if (reg >= (u64)hw_mgt->mailbox_bar_size ||
	    reg + len > (u64)hw_mgt->mailbox_bar_size) {
		dev_err_once(hw_mgt->common->dev,
			     "mbx read out of range: reg=0x%llx len=%u bar_size=%pa\n",
			     reg, len, &hw_mgt->mailbox_bar_size);
		return;
	}
	for (i = 0; i < len / 4; i++)
		data[i] = nbl_mbx_rd32(hw_mgt, reg + i * sizeof(u32));
}

static void nbl_hw_write_mbx_regs(struct nbl_hw_mgt *hw_mgt, u64 reg,
				  const u32 *data, u32 len)
{
	u32 i;

	if (len % 4)
		return;
	if (reg >= (u64)hw_mgt->mailbox_bar_size ||
	    reg + len > (u64)hw_mgt->mailbox_bar_size) {
		dev_err_once(hw_mgt->common->dev,
			     "mbx write out of range: reg=0x%llx len=%u bar_size=%pa\n",
			     reg, len, &hw_mgt->mailbox_bar_size);
		return;
	}
	for (i = 0; i < len / 4; i++)
		nbl_mbx_wr32(hw_mgt, reg + i * sizeof(u32), data[i]);
}

/*
 * Flush posted mailbox-BAR writes by reading back through the same
 * BAR. A read to the same PCI function completes only after prior
 * posted writes targeting it have been accepted, so this write-then-
 * read-back pair gives the same guarantee as nbl_flush_writes().
 *
 * This must be used instead of nbl_flush_writes() in any path that can
 * run on a non-management PF: the mailbox BAR is fully mapped on every
 * function, while the MEMORY BAR dummy register used by
 * nbl_flush_writes() lies inside the 64 MiB control-PF-only aperture.
 */
static void nbl_hw_flush_mbx_write(struct nbl_hw_mgt *hw_mgt, u64 reg)
{
	u32 data;

	nbl_hw_read_mbx_regs(hw_mgt, reg, &data, sizeof(data));
}

static void nbl_hw_rd_regs(struct nbl_hw_mgt *hw_mgt, u64 reg, u32 *data,
			   u32 len)
{
	u32 size = len / 4;
	u32 i;

	if (len % 4)
		return;
	for (i = 0; i < size; i++)
		data[i] = rd32(hw_mgt->hw_addr, reg + i * sizeof(u32));
}

static void nbl_hw_wr_regs(struct nbl_hw_mgt *hw_mgt, u64 reg, const u32 *data,
			   u32 len)
{
	u32 size = len / 4;
	u32 i;

	if (len % 4)
		return;
	for (i = 0; i < size; i++)
		wr32(hw_mgt->hw_addr, reg + i * sizeof(u32), data[i]);
}

static void nbl_hw_rd_regs_lock(struct nbl_hw_mgt *hw_mgt, u64 reg, u32 *data,
				u32 len)
{
	u32 size = len / 4;
	u32 i;

	if (len % 4)
		return;

	spin_lock(&hw_mgt->reg_lock);

	for (i = 0; i < size; i++)
		data[i] = rd32(hw_mgt->hw_addr, reg + i * sizeof(u32));
	spin_unlock(&hw_mgt->reg_lock);
}

static void nbl_hw_wr_regs_lock(struct nbl_hw_mgt *hw_mgt, u64 reg,
				const u32 *data, u32 len)
{
	u32 size = len / 4;
	u32 i;

	if (len % 4)
		return;
	spin_lock(&hw_mgt->reg_lock);
	for (i = 0; i < size; i++)
		wr32(hw_mgt->hw_addr, reg + i * sizeof(u32), data[i]);
	spin_unlock(&hw_mgt->reg_lock);
}

/*
 * Only call this when has_ctrl=true, which maps enough space
 * (bar_len - 8192) to cover NBL_HW_DUMMY_REG (0x1300904).
 * The flow/design guarantees this is only called in the
 * has_ctrl path.
 */
static void nbl_flush_writes(struct nbl_hw_mgt *hw_mgt)
{
	nbl_hw_rd32(hw_mgt, NBL_HW_DUMMY_REG);
}

/*
 * Registers reset to zero after cold boot / FLR / bus reset. Firmware
 * programs valid values before driver probe, so zero is only seen on
 * hardware fault or register read failure. Initialize data=0 to guard
 * against nbl_hw_read_mbx_regs() early-return on bounds-check failure.
 */
static void nbl_hw_get_fw_eth_map(struct nbl_hw_mgt *hw_mgt, u32 *eth_map)
{
	u32 data = 0;

	nbl_hw_read_mbx_regs(hw_mgt, NBL_FW_BOARD_DW6_OFFSET, &data,
			     sizeof(data));
	*eth_map = FIELD_GET(NBL_FW_BOARD_DW6_ETH_BITMAP_MASK, data);
}

static u32 nbl_hw_get_quirks(struct nbl_hw_mgt *hw_mgt)
{
	u32 quirks = 0;

	/*
	 * Read quirk bits from mailbox register.
	 * All supported firmware implement the quirk ABI,
	 * firmware always populates NBL_LEONIS_QUIRKS_OFFSET.
	 * Value ~0U indicates no active quirks.
	 */
	nbl_hw_read_mbx_regs(hw_mgt, NBL_LEONIS_QUIRKS_OFFSET, &quirks,
			     sizeof(u32));

	if (quirks == ~0u)
		return 0;

	return quirks;
}

static void nbl_configure_dped_checksum(struct nbl_hw_mgt *hw_mgt)
{
	u32 data = 0;

	/* DPED dped_l4_ck_cmd_40 for sctp */
	spin_lock(&hw_mgt->reg_lock);
	nbl_hw_rd_regs(hw_mgt, NBL_DPED_L4_CK_CMD_40_ADDR, &data, sizeof(data));
	data |= FIELD_PREP(NBL_DPED_L4_CK_CMD_40_EN_MASK, 1);
	nbl_hw_wr_regs(hw_mgt, NBL_DPED_L4_CK_CMD_40_ADDR, &data, sizeof(data));
	spin_unlock(&hw_mgt->reg_lock);
}

static void nbl_dped_init(struct nbl_hw_mgt *hw_mgt)
{
	spin_lock(&hw_mgt->reg_lock);
	nbl_hw_wr32(hw_mgt, NBL_DPED_VLAN_OFFSET, 0xC);
	nbl_hw_wr32(hw_mgt, NBL_DPED_DSCP_OFFSET_0, 0x8);
	nbl_hw_wr32(hw_mgt, NBL_DPED_DSCP_OFFSET_1, 0x4);
	spin_unlock(&hw_mgt->reg_lock);
	/* dped checksum offload */
	nbl_configure_dped_checksum(hw_mgt);
}

static void nbl_uped_init(struct nbl_hw_mgt *hw_mgt)
{
	u32 hw_edit = 0;

	/* V4 TCP: l3_len = 0 */
	spin_lock(&hw_mgt->reg_lock);
	nbl_hw_rd_regs(hw_mgt, NBL_UPED_HW_EDT_PROF_TABLE(NBL_UPED_V4_TCP_IDX),
		       &hw_edit, sizeof(hw_edit));
	hw_edit &= ~NBL_PED_HW_EDIT_PROFILE_L3_LEN_MASK;
	nbl_hw_wr_regs(hw_mgt, NBL_UPED_HW_EDT_PROF_TABLE(NBL_UPED_V4_TCP_IDX),
		       &hw_edit, sizeof(hw_edit));

	/* V6 TCP: l3_len = 1 */
	nbl_hw_rd_regs(hw_mgt, NBL_UPED_HW_EDT_PROF_TABLE(NBL_UPED_V6_TCP_IDX),
		       &hw_edit, sizeof(hw_edit));
	hw_edit = (hw_edit & ~NBL_PED_HW_EDIT_PROFILE_L3_LEN_MASK) |
		  FIELD_PREP(NBL_PED_HW_EDIT_PROFILE_L3_LEN_MASK, 1);
	nbl_hw_wr_regs(hw_mgt, NBL_UPED_HW_EDT_PROF_TABLE(NBL_UPED_V6_TCP_IDX),
		       &hw_edit, sizeof(hw_edit));
	spin_unlock(&hw_mgt->reg_lock);
}

static int nbl_shaping_eth_init(struct nbl_hw_mgt *hw_mgt, u8 eth_id, u8 speed)
{
	struct nbl_shaping_dvn_dport_u dvn_dport = { 0 };
	struct nbl_shaping_dport_u dport = { 0 };
	u32 rate, half_rate;
	u32 depth;
	u64 low_val, high_val;

	switch (speed) {
	case NBL_FW_PORT_SPEED_100G:
		rate = 100000;
		break;
	case NBL_FW_PORT_SPEED_50G:
		rate = 50000;
		break;
	case NBL_FW_PORT_SPEED_25G:
		rate = 25000;
		break;
	case NBL_FW_PORT_SPEED_10G:
		rate = 10000;
		break;
	default:
		dev_err(hw_mgt->common->dev,
			"Unsupported port speed %u for eth%u\n", speed, eth_id);
		return -EINVAL;
	}

	half_rate = rate / 2;
	depth = max_t(u32, rate * 2, NBL_LR_LEONIS_NET_BUCKET_DEPTH);

	/* 1. clear valid first
	 * dport and dvn_dport are zero-initialised above, so VALID=0 already
	 */
	spin_lock(&hw_mgt->reg_lock);
	nbl_hw_wr_regs(hw_mgt, NBL_SHAPING_DPORT_REG(eth_id), dport.data,
		       sizeof(dport));
	nbl_hw_wr_regs(hw_mgt, NBL_SHAPING_DVN_DPORT_REG(eth_id),
		       dvn_dport.data, sizeof(dvn_dport));

	/* 2. write config words (valid=0, safe) */
	low_val = FIELD_PREP(NBL_DPORT_CIR_MASK, rate) |
		  FIELD_PREP(NBL_DPORT_PIR_MASK, rate) |
		  FIELD_PREP(NBL_DPORT_DEPTH_MASK, depth) |
		  FIELD_PREP(NBL_DPORT_CBS_MASK_LOW, depth & 0x3F);
	high_val = FIELD_PREP(NBL_DPORT_CBS_MASK_HIGH, depth >> 6) |
		   FIELD_PREP(NBL_DPORT_PBS_MASK, depth);
	/* Fixed split, independent of host endian */
	dport.data[0] = lower_32_bits(low_val);
	dport.data[1] = upper_32_bits(low_val);
	dport.data[2] = lower_32_bits(high_val);
	dport.data[3] = upper_32_bits(high_val);

	low_val = FIELD_PREP(NBL_DPORT_CIR_MASK, half_rate) |
		  FIELD_PREP(NBL_DPORT_PIR_MASK, rate) |
		  FIELD_PREP(NBL_DPORT_DEPTH_MASK, depth) |
		  FIELD_PREP(NBL_DPORT_CBS_MASK_LOW, depth & 0x3F);
	high_val = FIELD_PREP(NBL_DPORT_CBS_MASK_HIGH, depth >> 6) |
		   FIELD_PREP(NBL_DPORT_PBS_MASK, depth);
	dvn_dport.data[0] = lower_32_bits(low_val);
	dvn_dport.data[1] = upper_32_bits(low_val);
	dvn_dport.data[2] = lower_32_bits(high_val);
	dvn_dport.data[3] = upper_32_bits(high_val);

	nbl_hw_wr_regs(hw_mgt, NBL_SHAPING_DPORT_REG(eth_id), dport.data,
		       sizeof(dport));
	nbl_hw_wr_regs(hw_mgt, NBL_SHAPING_DVN_DPORT_REG(eth_id),
		       dvn_dport.data, sizeof(dvn_dport));

	/* 3. commit: set valid last */
	low_val = FIELD_PREP(NBL_DPORT_VALID_MASK, 1);
	dport.data[0] |= lower_32_bits(low_val);

	low_val = FIELD_PREP(NBL_DPORT_VALID_MASK, 1);
	dvn_dport.data[0] |= lower_32_bits(low_val);

	nbl_hw_wr_regs(hw_mgt, NBL_SHAPING_DPORT_REG(eth_id), dport.data,
		       sizeof(dport));
	nbl_hw_wr_regs(hw_mgt, NBL_SHAPING_DVN_DPORT_REG(eth_id),
		       dvn_dport.data, sizeof(dvn_dport));
	spin_unlock(&hw_mgt->reg_lock);
	return 0;
}

static int nbl_shaping_init(struct nbl_hw_mgt *hw_mgt, u8 speed)
{
#define NBL_SHAPING_FLUSH_INTERVAL 128
	struct nbl_shaping_net_u net_shaping = { 0 };
	u32 eth_bitmap = 0;
	u32 reg_val;
	int ret;
	int i;

	nbl_hw_get_fw_eth_map(hw_mgt, &eth_bitmap);
	for (i = 0; i < NBL_MAX_ETHERNET; i++) {
		if (!(eth_bitmap & BIT(i)))
			continue;
		ret = nbl_shaping_eth_init(hw_mgt, i, speed);
		if (ret)
			return ret;
	}
	nbl_hw_rd_regs_lock(hw_mgt, NBL_DSCH_PSHA_EN_ADDR, &reg_val,
			    sizeof(reg_val));
	reg_val &= ~NBL_DSCH_PSHA_EN_MASK;
	reg_val |= FIELD_PREP(NBL_DSCH_PSHA_EN_MASK,
			      eth_bitmap & GENMASK(3, 0));
	nbl_hw_wr_regs_lock(hw_mgt, NBL_DSCH_PSHA_EN_ADDR, &reg_val,
			    sizeof(reg_val));

	for (i = 0; i < NBL_MAX_FUNC; i++) {
		nbl_hw_wr_regs_lock(hw_mgt, NBL_SHAPING_NET_REG(i),
				    net_shaping.data,
				    sizeof(net_shaping));
		if ((i + 1) % NBL_SHAPING_FLUSH_INTERVAL == 0)
			nbl_flush_writes(hw_mgt);
	}
	nbl_flush_writes(hw_mgt);
	return 0;
}

static void nbl_dsch_qid_max_init(struct nbl_hw_mgt *hw_mgt)
{
	u32 quanta = 0;
	u32 qid_max = 0;

	quanta = FIELD_PREP(NBL_DSCH_VN_QUANTA_H_QUA_MASK, NBL_HOST_QUANTA) |
		 FIELD_PREP(NBL_DSCH_VN_QUANTA_E_QUA_MASK, NBL_ECPU_QUANTA);
	spin_lock(&hw_mgt->reg_lock);
	nbl_hw_wr_regs(hw_mgt, NBL_DSCH_VN_QUANTA_ADDR, &quanta,
		       sizeof(quanta));
	nbl_hw_rd_regs(hw_mgt, NBL_DSCH_HOST_QID_MAX, &qid_max,
		       sizeof(qid_max));
	qid_max &= ~NBL_DSCH_HOST_QID_MAX_MASK;
	qid_max |= FIELD_PREP(NBL_DSCH_HOST_QID_MAX_MASK, NBL_MAX_QUEUE_ID);
	nbl_hw_wr_regs(hw_mgt, NBL_DSCH_HOST_QID_MAX, &qid_max,
		       sizeof(qid_max));
	spin_unlock(&hw_mgt->reg_lock);
}

static int nbl_ustore_init(struct nbl_hw_mgt *hw_mgt, u8 eth_num)
{
	u32 eth_bitmap = 0;
	u32 drop_th = 0;
	u32 pkt_len = 0;
	u32 reg_val = 0;
	int i;

	/*
	 * eth_num is validated in the resource layer:
	 * nbl_res_init_pf_num() requires 1/2/4 PFs, and
	 * nbl_res_ctrl_dev_setup_eth_info() requires max_pf == eth_num.
	 * This is a defensive check only; if it triggers, the resource
	 * layer validation was bypassed, which is a bug.
	 */
	if (WARN_ON(eth_num != 1 && eth_num != 2 && eth_num != 4))
		return -EINVAL;
	/* Read current packet length config
	 *(to preserve other fields while updating 'min')
	 */
	spin_lock(&hw_mgt->reg_lock);
	nbl_hw_rd_regs(hw_mgt, NBL_USTORE_PKT_LEN_ADDR, &pkt_len,
		       sizeof(pkt_len));
	/* min arp packet length 42 (14 + 28) */
	pkt_len &= ~NBL_USTORE_PKT_LEN_MIN_MASK;
	pkt_len |= FIELD_PREP(NBL_USTORE_PKT_LEN_MIN_MASK, 42);
	nbl_hw_wr_regs(hw_mgt, NBL_USTORE_PKT_LEN_ADDR, &pkt_len,
		       sizeof(pkt_len));

	drop_th |= FIELD_PREP(NBL_USTORE_PORT_DROP_TH_EN_MASK, 1);
	if (eth_num == 1)
		drop_th |= FIELD_PREP(NBL_USTORE_PORT_DROP_TH_DISC_TH_MASK,
				      NBL_USTORE_SINGLE_ETH_DROP_TH);
	else if (eth_num == 2)
		drop_th |= FIELD_PREP(NBL_USTORE_PORT_DROP_TH_DISC_TH_MASK,
				      NBL_USTORE_DUAL_ETH_DROP_TH);
	else
		drop_th |= FIELD_PREP(NBL_USTORE_PORT_DROP_TH_DISC_TH_MASK,
				      NBL_USTORE_QUAD_ETH_DROP_TH);
	nbl_hw_get_fw_eth_map(hw_mgt, &eth_bitmap);
	for (i = 0; i < NBL_MAX_ETHERNET; i++) {
		if (!(eth_bitmap & BIT(i)))
			continue;
		nbl_hw_rd_regs(hw_mgt, NBL_USTORE_PORT_DROP_TH_REG_ARR(i),
			       &reg_val, sizeof(reg_val));
		reg_val &= ~(NBL_USTORE_PORT_DROP_TH_EN_MASK |
			    NBL_USTORE_PORT_DROP_TH_DISC_TH_MASK);
		reg_val |= drop_th;
		nbl_hw_wr_regs(hw_mgt, NBL_USTORE_PORT_DROP_TH_REG_ARR(i),
			       &reg_val, sizeof(reg_val));
	}

	/* Clear port drop/truncate counters by reading them
	 * (hardware has read-to-clear behavior for these registers)
	 */
	for (i = 0; i < NBL_MAX_ETHERNET; i++) {
		if (!(eth_bitmap & BIT(i)))
			continue;
		nbl_hw_rd32(hw_mgt, NBL_USTORE_BUF_PORT_DROP_PKT(i));
		nbl_hw_rd32(hw_mgt, NBL_USTORE_BUF_PORT_TRUN_PKT(i));
	}
	spin_unlock(&hw_mgt->reg_lock);
	return 0;
}

static void nbl_dstore_init(struct nbl_hw_mgt *hw_mgt, u8 speed)
{
	u32 eth_bitmap = 0;
	u32 drop_th = 0;
	u32 fc_th = 0;
	u32 bp_th = 0;
	int i;

	for (i = 0; i < NBL_DSTORE_PORT_DROP_TH_DEPTH; i++) {
		spin_lock(&hw_mgt->reg_lock);
		nbl_hw_rd_regs(hw_mgt, NBL_DSTORE_PORT_DROP_TH_REG(i), &drop_th,
			       sizeof(drop_th));
		drop_th &= ~NBL_DSTORE_PORT_DROP_EN_MASK;
		nbl_hw_wr_regs(hw_mgt, NBL_DSTORE_PORT_DROP_TH_REG(i), &drop_th,
			       sizeof(drop_th));
		spin_unlock(&hw_mgt->reg_lock);
	}

	spin_lock(&hw_mgt->reg_lock);
	nbl_hw_rd_regs(hw_mgt, NBL_DSTORE_DISC_BP_TH, &bp_th, sizeof(bp_th));
	bp_th |= FIELD_PREP(NBL_DSTORE_DISC_BP_TH_EN_MASK, 1);
	nbl_hw_wr_regs(hw_mgt, NBL_DSTORE_DISC_BP_TH, &bp_th, sizeof(bp_th));
	spin_unlock(&hw_mgt->reg_lock);

	nbl_hw_get_fw_eth_map(hw_mgt, &eth_bitmap);
	for (i = 0; i < NBL_MAX_ETHERNET; i++) {
		if (!(eth_bitmap & BIT(i)))
			continue;
		spin_lock(&hw_mgt->reg_lock);
		nbl_hw_rd_regs(hw_mgt, NBL_DSTORE_D_DPORT_FC_TH_REG(i), &fc_th,
			       sizeof(fc_th));
		fc_th &= ~(NBL_DSTORE_D_DPORT_FC_XOFF_TH_MASK |
			   NBL_DSTORE_D_DPORT_FC_XON_TH_MASK);
		if (speed == NBL_FW_PORT_SPEED_100G) {
			fc_th |=
				FIELD_PREP(NBL_DSTORE_D_DPORT_FC_XOFF_TH_MASK,
					   NBL_DSTORE_DROP_XOFF_TH_100G) |
				FIELD_PREP(NBL_DSTORE_D_DPORT_FC_XON_TH_MASK,
					   NBL_DSTORE_DROP_XON_TH_100G);
		} else {
			fc_th |=
				FIELD_PREP(NBL_DSTORE_D_DPORT_FC_XOFF_TH_MASK,
					   NBL_DSTORE_DROP_XOFF_TH) |
				FIELD_PREP(NBL_DSTORE_D_DPORT_FC_XON_TH_MASK,
					   NBL_DSTORE_DROP_XON_TH);
		}

		fc_th |= FIELD_PREP(NBL_DSTORE_D_DPORT_FC_FC_EN_MASK, 1);
		nbl_hw_wr_regs(hw_mgt, NBL_DSTORE_D_DPORT_FC_TH_REG(i), &fc_th,
			       sizeof(fc_th));
		spin_unlock(&hw_mgt->reg_lock);
	}
}

static void nbl_dvn_descreq_num_cfg(struct nbl_hw_mgt *hw_mgt, u8 descreq_num)
{
	u8 split_ring_num = (descreq_num >> 3) & 0x1;
	u8 ring_num = descreq_num & 0x7;
	u32 num_cfg;
	u32 reg_val;

	spin_lock(&hw_mgt->reg_lock);
	nbl_hw_rd_regs(hw_mgt, NBL_DVN_DESCREQ_NUM_CFG, &reg_val,
		       sizeof(reg_val));

	num_cfg = FIELD_PREP(NBL_DVN_DESCREQ_NUM_CFG_AVRING_DESREQ_NUM_CFG_MASK,
			     split_ring_num) |
		  FIELD_PREP(NBL_DVN_DESCREQ_NUM_CFG_PACKED_L1_NUM_MASK,
			     ring_num);
	reg_val &= ~(NBL_DVN_DESCREQ_NUM_CFG_AVRING_DESREQ_NUM_CFG_MASK |
		NBL_DVN_DESCREQ_NUM_CFG_PACKED_L1_NUM_MASK);
	reg_val |= num_cfg;
	nbl_hw_wr_regs(hw_mgt, NBL_DVN_DESCREQ_NUM_CFG, &reg_val,
		       sizeof(reg_val));
	spin_unlock(&hw_mgt->reg_lock);
}

static void nbl_dvn_init(struct nbl_hw_mgt *hw_mgt, u8 speed)
{
	u32 timeout = 0;
	u32 ro_flag = 0;

	nbl_hw_wr32(hw_mgt, NBL_DVN_ECPU_QUEUE_NUM, 0);
	timeout = FIELD_PREP(NBL_DVN_DESC_WR_MERGE_TIMEOUT_CFG_CYCLE_MASK,
			     DEFAULT_DVN_DESC_WR_MERGE_TIMEOUT_MAX);
	nbl_hw_wr_regs_lock(hw_mgt, NBL_DVN_DESC_WR_MERGE_TIMEOUT, &timeout,
			    sizeof(timeout));
	spin_lock(&hw_mgt->reg_lock);
	nbl_hw_rd_regs(hw_mgt, NBL_DVN_DIF_REQ_RD_RO_FLAG, &ro_flag,
		       sizeof(ro_flag));
	if (pcie_relaxed_ordering_enabled(hw_mgt->common->pdev)) {
		ro_flag |=
			FIELD_PREP(NBL_DVN_DIF_REQ_RD_RO_FLAG_DESC_RO_EN_MASK,
				   1) |
			FIELD_PREP(NBL_DVN_DIF_REQ_RD_RO_FLAG_DATA_RO_EN_MASK,
				   1) |
			FIELD_PREP(NBL_DVN_DIF_REQ_RD_RO_FLAG_AVRING_RO_EN_MASK,
				   1);
	} else {
		ro_flag &=
			~(FIELD_PREP(NBL_DVN_DIF_REQ_RD_RO_FLAG_DESC_RO_EN_MASK,
				     1) |
			FIELD_PREP(NBL_DVN_DIF_REQ_RD_RO_FLAG_DATA_RO_EN_MASK,
				   1) |
			FIELD_PREP(NBL_DVN_DIF_REQ_RD_RO_FLAG_AVRING_RO_EN_MASK,
				   1));
	}
	nbl_hw_wr_regs(hw_mgt, NBL_DVN_DIF_REQ_RD_RO_FLAG, &ro_flag,
		       sizeof(ro_flag));
	spin_unlock(&hw_mgt->reg_lock);
	if (speed == NBL_FW_PORT_SPEED_100G)
		nbl_dvn_descreq_num_cfg(hw_mgt,
					DEFAULT_DVN_100G_DESCREQ_NUMCFG);
	else
		nbl_dvn_descreq_num_cfg(hw_mgt, DEFAULT_DVN_DESCREQ_NUMCFG);
}

static void nbl_uvn_init(struct nbl_hw_mgt *hw_mgt)
{
	u16 wr_timeout = NBL_UVN_DESC_WR_TIMEOUT_VAL;
	u32 timeout = NBL_UVN_DESC_RD_WAIT_TICKS;
	u32 prefetch_init = 0;
	bool ro_enabled;
	u32 flag = 0;
	u32 mask = 0;
	u32 quirks;
	u32 reg_val;

	spin_lock(&hw_mgt->reg_lock);
	nbl_hw_wr32(hw_mgt, NBL_UVN_ECPU_QUEUE_NUM, 0);
	nbl_hw_wr32(hw_mgt, NBL_UVN_DESC_RD_WAIT, timeout);
	nbl_hw_rd_regs(hw_mgt, NBL_UVN_DESC_WR_TIMEOUT,
		       &reg_val, sizeof(reg_val));
	reg_val &= ~NBL_UVN_DESC_WR_TIMEOUT_NUM_MASK;
	reg_val |= FIELD_PREP(NBL_UVN_DESC_WR_TIMEOUT_NUM_MASK, wr_timeout);
	nbl_hw_wr_regs(hw_mgt, NBL_UVN_DESC_WR_TIMEOUT, &reg_val,
		       sizeof(reg_val));
	ro_enabled = pcie_relaxed_ordering_enabled(hw_mgt->common->pdev);

	nbl_hw_rd_regs(hw_mgt, NBL_UVN_DIF_REQ_RO_FLAG, &flag, sizeof(flag));
	if (ro_enabled) {
		flag |= FIELD_PREP(NBL_UVN_DIF_REQ_RO_FLAG_AVAIL_RD_MASK, 1) |
		FIELD_PREP(NBL_UVN_DIF_REQ_RO_FLAG_DESC_RD_MASK, 1) |
		FIELD_PREP(NBL_UVN_DIF_REQ_RO_FLAG_PKT_WR_MASK, 1);
		flag &= ~FIELD_PREP(NBL_UVN_DIF_REQ_RO_FLAG_DESC_WR_MASK, 1);
	} else {
		flag &= ~(FIELD_PREP(NBL_UVN_DIF_REQ_RO_FLAG_AVAIL_RD_MASK, 1) |
			  FIELD_PREP(NBL_UVN_DIF_REQ_RO_FLAG_DESC_RD_MASK, 1) |
			  FIELD_PREP(NBL_UVN_DIF_REQ_RO_FLAG_PKT_WR_MASK, 1) |
			  FIELD_PREP(NBL_UVN_DIF_REQ_RO_FLAG_DESC_WR_MASK, 1));
	}
	nbl_hw_wr_regs(hw_mgt, NBL_UVN_DIF_REQ_RO_FLAG, &flag, sizeof(flag));

	nbl_hw_rd_regs(hw_mgt, NBL_UVN_QUEUE_ERR_MASK, &mask, sizeof(mask));
	mask |= FIELD_PREP(NBL_UVN_QUEUE_ERR_MASK_DIF_ERR_MASK, 1);

	nbl_hw_wr_regs(hw_mgt, NBL_UVN_QUEUE_ERR_MASK, &mask, sizeof(mask));

	spin_unlock(&hw_mgt->reg_lock);
	quirks = nbl_hw_get_quirks(hw_mgt);
	/*
	 * sel=0: use configured num; sel=1: use internal calc (max 32)
	 * Default is sel=1, unless NBL_QUIRK_UVN_PREFETCH_ALIGN is set,
	 * in which case override to sel=0.
	 */
	spin_lock(&hw_mgt->reg_lock);
	nbl_hw_rd_regs(hw_mgt, NBL_UVN_DESC_PREFETCH_INIT, &reg_val,
		       sizeof(reg_val));
	prefetch_init =
		FIELD_PREP(NBL_UVN_DESC_PREFETCH_INIT_NUM_MASK,
			   NBL_UVN_DESC_PREFETCH_NUM) |
		FIELD_PREP(NBL_UVN_DESC_PREFETCH_INIT_SEL_MASK,
			   (quirks & NBL_QUIRK_UVN_PREFETCH_ALIGN) ? 0 : 1);
	reg_val &= ~(NBL_UVN_DESC_PREFETCH_INIT_NUM_MASK |
		NBL_UVN_DESC_PREFETCH_INIT_SEL_MASK);
	reg_val |= prefetch_init;
	nbl_hw_wr_regs(hw_mgt, NBL_UVN_DESC_PREFETCH_INIT, &reg_val,
		       sizeof(reg_val));
	spin_unlock(&hw_mgt->reg_lock);
}

static void nbl_uqm_init(struct nbl_hw_mgt *hw_mgt)
{
	u32 que_type = 0;
	u32 cnt = 0;
	int i;

	spin_lock(&hw_mgt->reg_lock);
	nbl_hw_wr_regs(hw_mgt, NBL_UQM_FWD_DROP_CNT, &cnt, sizeof(cnt));

	nbl_hw_wr_regs(hw_mgt, NBL_UQM_DROP_PKT_CNT, &cnt, sizeof(cnt));
	nbl_hw_wr_regs(hw_mgt, NBL_UQM_DROP_PKT_SLICE_CNT, &cnt, sizeof(cnt));
	nbl_hw_wr_regs(hw_mgt, NBL_UQM_DROP_PKT_LEN_ADD_CNT, &cnt, sizeof(cnt));
	nbl_hw_wr_regs(hw_mgt, NBL_UQM_DROP_HEAD_PNTR_ADD_CNT, &cnt,
		       sizeof(cnt));
	nbl_hw_wr_regs(hw_mgt, NBL_UQM_DROP_WEIGHT_ADD_CNT, &cnt, sizeof(cnt));

	for (i = 0; i < NBL_UQM_PORT_DROP_DEPTH; i++) {
		nbl_hw_wr_regs(hw_mgt,
			       NBL_UQM_PORT_DROP_PKT_CNT + (sizeof(cnt) * i),
			       &cnt, sizeof(cnt));
		nbl_hw_wr_regs(hw_mgt,
			       NBL_UQM_PORT_DROP_PKT_SLICE_CNT +
				       (sizeof(cnt) * i),
			       &cnt, sizeof(cnt));
		nbl_hw_wr_regs(hw_mgt,
			       NBL_UQM_PORT_DROP_PKT_LEN_ADD_CNT +
				       (sizeof(cnt) * i),
			       &cnt, sizeof(cnt));
		nbl_hw_wr_regs(hw_mgt,
			       NBL_UQM_PORT_DROP_HEAD_PNTR_ADD_CNT +
				       (sizeof(cnt) * i),
			       &cnt, sizeof(cnt));
		nbl_hw_wr_regs(hw_mgt,
			       NBL_UQM_PORT_DROP_WEIGHT_ADD_CNT +
				       (sizeof(cnt) * i),
			       &cnt, sizeof(cnt));
	}

	for (i = 0; i < NBL_UQM_DPORT_DROP_DEPTH; i++)
		nbl_hw_wr_regs(hw_mgt,
			       NBL_UQM_DPORT_DROP_CNT + (sizeof(cnt) * i), &cnt,
			       sizeof(cnt));
	/* bit0: 0=bp mode, 1=drop mode, resv bit1-31 */
	nbl_hw_wr_regs(hw_mgt, NBL_UQM_QUE_TYPE, &que_type, sizeof(que_type));
	spin_unlock(&hw_mgt->reg_lock);
}

static int nbl_dp_init(struct nbl_hw_mgt *hw_mgt, u8 speed, u8 eth_num)
{
	int ret;

	nbl_dped_init(hw_mgt);
	nbl_uped_init(hw_mgt);
	ret = nbl_shaping_init(hw_mgt, speed);
	if (ret)
		return ret;
	nbl_dsch_qid_max_init(hw_mgt);
	ret = nbl_ustore_init(hw_mgt, eth_num);
	if (ret)
		return ret;
	nbl_dstore_init(hw_mgt, speed);
	nbl_dvn_init(hw_mgt, speed);
	nbl_uvn_init(hw_mgt);
	nbl_uqm_init(hw_mgt);
	return 0;
}

static void nbl_host_padpt_init(struct nbl_hw_mgt *hw_mgt)
{
	/* padpt flow  control register */
	spin_lock(&hw_mgt->reg_lock);
	nbl_hw_wr32(hw_mgt, NBL_HOST_PADPT_HOST_CFG_FC_CPLH_UP,
		    NBL_HOST_PADPT_CFG_FC_CPLH_UP_VAL);
	nbl_hw_wr32(hw_mgt, NBL_HOST_PADPT_HOST_CFG_FC_PD_DN,
		    NBL_HOST_PADPT_CFG_FC_PD_DN_VAL);
	nbl_hw_wr32(hw_mgt, NBL_HOST_PADPT_HOST_CFG_FC_PH_DN,
		    NBL_HOST_PADPT_CFG_FC_PH_DN_VAL);
	nbl_hw_wr32(hw_mgt, NBL_HOST_PADPT_HOST_CFG_FC_NPH_DN,
		    NBL_HOST_PADPT_CFG_FC_NPH_DN_VAL);
	spin_unlock(&hw_mgt->reg_lock);
}

static void nbl_intf_init(struct nbl_hw_mgt *hw_mgt)
{
	nbl_host_padpt_init(hw_mgt);
}

static void nbl_hw_set_driver_status(struct nbl_hw_mgt *hw_mgt, bool active)
{
	u32 status;

	spin_lock(&hw_mgt->reg_lock);
	status = nbl_hw_rd32(hw_mgt, NBL_DRIVER_STATUS_REG);

	status &= ~BIT(NBL_DRIVER_STATUS_BIT);
	status |= FIELD_PREP(BIT(NBL_DRIVER_STATUS_BIT), active);

	nbl_hw_wr32(hw_mgt, NBL_DRIVER_STATUS_REG, status);
	spin_unlock(&hw_mgt->reg_lock);
}

/*
 * Setting driver status to false notifies firmware to clean up per-PF
 * hardware state such as qinfo registers.
 *
 * Note: firmware does NOT automatically revert chip-wide registers
 * configured in this init flow. Those chip-wide settings remain valid
 * until chip reset or explicitly overwritten by driver.
 *
 * This deinit_module only clears driver active status and flush writes.
 * It does NOT reset or restore chip-wide datapath registers.
 *
 * Caller must ensure no new DMA is initiated after this point.
 * The mailbox channel is stopped by nbl_chan_teardown_queue()
 * before this function is called, so no in-flight mailbox DMA
 * remains.
 */
static void nbl_hw_deinit_module(struct nbl_hw_mgt *hw_mgt)
{
	nbl_hw_set_driver_status(hw_mgt, false);
	/* ensure registers written */
	nbl_flush_writes(hw_mgt);
	/*
	 * Firmware cleanup is asynchronous: there is no cleanup-complete
	 * status register in the current hardware revision.  The posted
	 * write flush above only ensures driver_status reaches the chip;
	 * firmware may still be performing per-PF state cleanup when this
	 * function returns.
	 */
}

static bool nbl_hw_eth_speed_valid(u8 speed)
{
	switch (speed) {
	case NBL_FW_PORT_SPEED_10G:
	case NBL_FW_PORT_SPEED_25G:
	case NBL_FW_PORT_SPEED_50G:
	case NBL_FW_PORT_SPEED_100G:
		return true;
	default:
		return false;
	}
}

static bool nbl_hw_eth_num_valid(u8 eth_num)
{
	return eth_num == 1 || eth_num == 2 || eth_num == 4;
}

/*
 * Full chip hardware initialization is handled by firmware.
 * This function only configures driver-level table entries and registers.
 */
static int nbl_hw_init_module(struct nbl_hw_mgt *hw_mgt, u8 eth_speed,
			      u8 eth_num)
{
	int ret;

	if (!nbl_hw_eth_speed_valid(eth_speed)) {
		dev_err(hw_mgt->common->dev, "Invalid eth_speed %u\n",
			eth_speed);
		return -EINVAL;
	}
	if (!nbl_hw_eth_num_valid(eth_num)) {
		dev_err(hw_mgt->common->dev, "Invalid eth_num %u\n", eth_num);
		return -EINVAL;
	}

	ret = nbl_dp_init(hw_mgt, eth_speed, eth_num);
	if (ret)
		return ret;
	nbl_intf_init(hw_mgt);
	nbl_hw_set_driver_status(hw_mgt, true);
	/* ensure registers written */
	nbl_flush_writes(hw_mgt);

	return 0;
}

/*
 * nbl_hw_set_mailbox_irq - read-modify-write NBL_MAILBOX_QINFO_MAP_REG_ARR
 *
 * The full RMW sequence is wrapped by reg_lock, so concurrent register
 * access from different CPUs is already serialized safely.
 * nbl_hw_cfg_mailbox_qinfo() programs the BDF fields during control-PF
 * init and clears MSIX_IDX/MSIX_IDX_VALID at the same time (they survive
 * kexec/forced unload without FLR), so mailbox MSIX routing for a PF
 * starts disarmed at init and is armed only by an explicit en_msix=true
 * call here.
 */
static void nbl_hw_set_mailbox_irq(struct nbl_hw_mgt *hw_mgt, u16 func_id,
				   bool en_msix, u16 gvec)
{
	u32 data = 0;

	spin_lock(&hw_mgt->reg_lock);
	nbl_hw_rd_regs(hw_mgt, NBL_MAILBOX_QINFO_MAP_REG_ARR(func_id), &data,
		       sizeof(data));
	data &= ~(NBL_MAILBOX_QINFO_MAP_MSIX_IDX_MASK |
		  NBL_MAILBOX_QINFO_MAP_MSIX_IDX_VALID_MASK);
	if (en_msix)
		data |= FIELD_PREP(NBL_MAILBOX_QINFO_MAP_MSIX_IDX_MASK,
				   gvec) |
			FIELD_PREP(NBL_MAILBOX_QINFO_MAP_MSIX_IDX_VALID_MASK,
				   1);

	nbl_hw_wr_regs(hw_mgt, NBL_MAILBOX_QINFO_MAP_REG_ARR(func_id), &data,
		       sizeof(data));
	spin_unlock(&hw_mgt->reg_lock);
	nbl_flush_writes(hw_mgt);
}

static void nbl_hw_cfg_msix_map(struct nbl_hw_mgt *hw_mgt, u16 func_id,
				bool valid, dma_addr_t dma_addr, u8 bus,
				u8 devid, u8 function)
{
	struct nbl_function_msix_map function_msix_map;

	memset(&function_msix_map, 0, sizeof(function_msix_map));
	if (valid) {
		function_msix_map.data[0] = lower_32_bits(dma_addr);
		function_msix_map.data[1] = upper_32_bits(dma_addr);
		/* use ctrl dev's bdf, because the dma memory was
		 * allocated by it
		 */
		function_msix_map.data[2] =
			FIELD_PREP(NBL_FUNCTION_MSIX_MAP_FUNCTION_MASK,
				   function) |
			FIELD_PREP(NBL_FUNCTION_MSIX_MAP_DEVID_MASK, devid) |
			FIELD_PREP(NBL_FUNCTION_MSIX_MAP_BUS_MASK, bus) |
			FIELD_PREP(NBL_FUNCTION_MSIX_MAP_VALID_MASK, 1);
	} else {
		/*
		 * reg_lock prevents concurrent CPU writes to the same
		 * function's MSIX entry, but cannot synchronize hardware DMA
		 * reads. Upper layer uses two-stage destruction + sync sleep
		 * to avoid torn hardware read of partial MSIX entry.
		 * Keep valid live dma address here, only clear VALID flag.
		 */
		function_msix_map.data[0] = lower_32_bits(dma_addr);
		function_msix_map.data[1] = upper_32_bits(dma_addr);
		function_msix_map.data[2] = 0;
	}

	nbl_hw_wr_regs_lock(hw_mgt,
			    NBL_PCOMPLETER_FUNCTION_MSIX_MAP_REG_ARR(func_id),
			    function_msix_map.data, sizeof(function_msix_map));
}

static void nbl_hw_cfg_msix_info(struct nbl_hw_mgt *hw_mgt, u16 func_id,
				 bool valid, u16 interrupt_id, u8 bus,
				 u8 devid, u8 function, bool msix_mask_en)
{
	u32 host_msix_fid = 0;
	struct nbl_host_msix_info msix_info;

	memset(&msix_info, 0, sizeof(msix_info));
	if (valid) {
		host_msix_fid =
			FIELD_PREP(NBL_PCOMPLETER_HOST_MSIX_FID_TABLE_FID_MASK,
				   func_id) |
			FIELD_PREP(NBL_PCOMPLETER_HOST_MSIX_FID_TABLE_VLD_MASK,
				   1);

		msix_info.data[1] =
			FIELD_PREP(NBL_HOST_MSIX_INFO_FUNCTION_MASK, function) |
			FIELD_PREP(NBL_HOST_MSIX_INFO_DEVID_MASK, devid) |
			FIELD_PREP(NBL_HOST_MSIX_INFO_BUS_MASK, bus) |
			FIELD_PREP(NBL_HOST_MSIX_INFO_VALID_MASK, 1);

		if (msix_mask_en)
			msix_info.data[1] |=
			FIELD_PREP(NBL_HOST_MSIX_INFO_MSIX_MASK_EN_MASK, 1);
	}
	spin_lock(&hw_mgt->reg_lock);
	/*
	 * Programming order rule:
	 * Enable: PADPT_HOST_MSIX_INFO -> PCOMPLETER_HOST_MSIX_FID_TABLE
	 * Teardown: reverse order, clear FID VLD first to avoid inconsistent
	 * state
	 */
	if (valid) {
		nbl_hw_wr_regs(hw_mgt,
			       NBL_PADPT_HOST_MSIX_INFO_REG_ARR(interrupt_id),
			       msix_info.data, sizeof(msix_info));
		nbl_hw_wr_regs(hw_mgt,
			       NBL_PCOMPLETER_HOST_MSIX_FID_TABLE(interrupt_id),
			       &host_msix_fid, sizeof(host_msix_fid));
	} else {
		nbl_hw_wr_regs(hw_mgt,
			       NBL_PCOMPLETER_HOST_MSIX_FID_TABLE(interrupt_id),
			       &host_msix_fid, sizeof(host_msix_fid));
		nbl_hw_wr_regs(hw_mgt,
			       NBL_PADPT_HOST_MSIX_INFO_REG_ARR(interrupt_id),
			       msix_info.data, sizeof(msix_info));
	}
	spin_unlock(&hw_mgt->reg_lock);
}

static void nbl_hw_update_mailbox_queue_tail_ptr(struct nbl_hw_mgt *hw_mgt,
						 u16 tail_ptr, u8 txrx)
{
	/* local_qid 0 and 1 denote rx and tx queue respectively */
	u32 local_qid = txrx;
	u32 value = ((u32)tail_ptr << 16) | local_qid;

	/* wmb for doorbell */
	wmb();
	nbl_mbx_wr32(hw_mgt, NBL_MAILBOX_NOTIFY_ADDR, value);
}

static void nbl_hw_config_mailbox_rxq(struct nbl_hw_mgt *hw_mgt,
				      dma_addr_t dma_addr, int size_bwid)
{
	struct nbl_mailbox_qinfo_cfg_table cfg_tbl;

	memset(&cfg_tbl, 0, sizeof(cfg_tbl));
	cfg_tbl.data[3] = FIELD_PREP(NBL_MAILBOX_QINFO_CFG_QUEUE_RST_MASK, 1);
	nbl_hw_write_mbx_regs(hw_mgt, NBL_MAILBOX_QINFO_CFG_RX_TABLE_ADDR,
			      cfg_tbl.data, sizeof(cfg_tbl));

	cfg_tbl.data[0] = lower_32_bits(dma_addr);
	cfg_tbl.data[1] = upper_32_bits(dma_addr);
	cfg_tbl.data[2] = FIELD_PREP(NBL_MAILBOX_QINFO_CFG_QUEUE_SIZE_BWID_MASK,
				     size_bwid);
	cfg_tbl.data[3] = FIELD_PREP(NBL_MAILBOX_QINFO_CFG_QUEUE_RST_MASK, 0) |
			  FIELD_PREP(NBL_MAILBOX_QINFO_CFG_QUEUE_EN_MASK, 1);
	nbl_hw_write_mbx_regs(hw_mgt, NBL_MAILBOX_QINFO_CFG_RX_TABLE_ADDR,
			      cfg_tbl.data, sizeof(cfg_tbl));
}

static void nbl_hw_config_mailbox_txq(struct nbl_hw_mgt *hw_mgt,
				      dma_addr_t dma_addr, int size_bwid)
{
	struct nbl_mailbox_qinfo_cfg_table cfg_tbl;

	memset(&cfg_tbl, 0, sizeof(cfg_tbl));
	cfg_tbl.data[3] = FIELD_PREP(NBL_MAILBOX_QINFO_CFG_QUEUE_RST_MASK, 1);
	nbl_hw_write_mbx_regs(hw_mgt, NBL_MAILBOX_QINFO_CFG_TX_TABLE_ADDR,
			      cfg_tbl.data, sizeof(cfg_tbl));

	cfg_tbl.data[0] = lower_32_bits(dma_addr);
	cfg_tbl.data[1] = upper_32_bits(dma_addr);
	cfg_tbl.data[2] = FIELD_PREP(NBL_MAILBOX_QINFO_CFG_QUEUE_SIZE_BWID_MASK,
				     size_bwid);
	cfg_tbl.data[3] = FIELD_PREP(NBL_MAILBOX_QINFO_CFG_QUEUE_RST_MASK, 0) |
			  FIELD_PREP(NBL_MAILBOX_QINFO_CFG_QUEUE_EN_MASK, 1);
	nbl_hw_write_mbx_regs(hw_mgt, NBL_MAILBOX_QINFO_CFG_TX_TABLE_ADDR,
			      cfg_tbl.data, sizeof(cfg_tbl));
}

static void nbl_hw_stop_mailbox_rxq(struct nbl_hw_mgt *hw_mgt)
{
	struct nbl_mailbox_qinfo_cfg_table cfg_tbl;

	memset(&cfg_tbl, 0, sizeof(cfg_tbl));
	cfg_tbl.data[3] = FIELD_PREP(NBL_MAILBOX_QINFO_CFG_QUEUE_RST_MASK, 1);
	nbl_hw_write_mbx_regs(hw_mgt, NBL_MAILBOX_QINFO_CFG_RX_TABLE_ADDR,
			      cfg_tbl.data, sizeof(cfg_tbl));
	/* Ensure QUEUE_RST has reached the device before caller proceeds */
	nbl_hw_flush_mbx_write(hw_mgt,
			       NBL_MAILBOX_QINFO_CFG_RX_TABLE_ADDR);
}

static void nbl_hw_stop_mailbox_txq(struct nbl_hw_mgt *hw_mgt)
{
	struct nbl_mailbox_qinfo_cfg_table cfg_tbl;

	memset(&cfg_tbl, 0, sizeof(cfg_tbl));
	cfg_tbl.data[3] = FIELD_PREP(NBL_MAILBOX_QINFO_CFG_QUEUE_RST_MASK, 1);
	nbl_hw_write_mbx_regs(hw_mgt, NBL_MAILBOX_QINFO_CFG_TX_TABLE_ADDR,
			      cfg_tbl.data, sizeof(cfg_tbl));
	/* Ensure QUEUE_RST has reached the device before caller proceeds */
	nbl_hw_flush_mbx_write(hw_mgt,
			       NBL_MAILBOX_QINFO_CFG_TX_TABLE_ADDR);
}

static void nbl_hw_get_host_pf_mask(struct nbl_hw_mgt *hw_mgt, u32 *pf_mask)
{
	nbl_hw_rd_regs_lock(hw_mgt, NBL_PCIE_HOST_K_PF_MASK_REG, pf_mask,
			    sizeof(*pf_mask));
}

static void nbl_hw_get_real_bus(struct nbl_hw_mgt *hw_mgt, u8 *bus)
{
	u32 data = 0;

	nbl_hw_rd_regs_lock(hw_mgt, NBL_PCIE_HOST_TL_CFG_BUSDEV, &data,
			    sizeof(data));
	*bus = FIELD_GET(NBL_PCIE_BUS_MASK, data);
}

static void nbl_hw_cfg_mailbox_qinfo(struct nbl_hw_mgt *hw_mgt, u16 func_id,
				     u8 bus, u8 devid, u8 function)
{
	u32 data = 0;

	/*
	 * Clear MSIX_IDX/MSIX_IDX_VALID together with the BDF fields:
	 * these registers survive kexec or a forced unload without FLR,
	 * so a VALID bit left over from a previous instance would keep
	 * mailbox interrupts routed to a global vector index that this
	 * instance may hand to a different function via cfg_msix_map().
	 * Routing is re-armed per PF by set_mailbox_irq() during each
	 * PF's own init (and disarmed again by intr_mgt_stop teardown).
	 */
	spin_lock(&hw_mgt->reg_lock);
	nbl_hw_rd_regs(hw_mgt, NBL_MAILBOX_QINFO_MAP_REG_ARR(func_id),
		       &data, sizeof(data));
	data &= ~(NBL_MAILBOX_QINFO_MAP_FUNCTION_MASK |
		  NBL_MAILBOX_QINFO_MAP_DEVID_MASK |
		  NBL_MAILBOX_QINFO_MAP_BUS_MASK |
		  NBL_MAILBOX_QINFO_MAP_MSIX_IDX_MASK |
		  NBL_MAILBOX_QINFO_MAP_MSIX_IDX_VALID_MASK);
	data |= FIELD_PREP(NBL_MAILBOX_QINFO_MAP_FUNCTION_MASK, function) |
	       FIELD_PREP(NBL_MAILBOX_QINFO_MAP_DEVID_MASK, devid) |
	       FIELD_PREP(NBL_MAILBOX_QINFO_MAP_BUS_MASK, bus);
	nbl_hw_wr_regs(hw_mgt, NBL_MAILBOX_QINFO_MAP_REG_ARR(func_id),
		       &data, sizeof(data));
	spin_unlock(&hw_mgt->reg_lock);
}

/*
 * Registers reset to zero after cold boot / FLR / bus reset. Firmware
 * programs valid values before driver probe, so zero is only seen on
 * hardware fault or register read failure. Initialize data=0 to guard
 * against nbl_hw_read_mbx_regs() early-return on bounds-check failure.
 */
static void nbl_hw_get_board_info(struct nbl_hw_mgt *hw_mgt,
				  struct nbl_board_port_info *board_info)
{
	u32 data = 0;

	nbl_hw_read_mbx_regs(hw_mgt, NBL_FW_BOARD_DW3_OFFSET, &data,
			     sizeof(data));
	board_info->eth_num = FIELD_GET(NBL_FW_BOARD_DW3_PORT_NUM_MASK, data);
	board_info->eth_speed =
		FIELD_GET(NBL_FW_BOARD_DW3_PORT_SPEED_MASK, data);
	board_info->p4_version =
		FIELD_GET(NBL_FW_BOARD_DW3_P4_VERSION_MASK, data);
}

static struct nbl_hw_ops hw_ops = {
	.init_module = nbl_hw_init_module,
	.deinit_module = nbl_hw_deinit_module,

	.cfg_msix_map = nbl_hw_cfg_msix_map,
	.cfg_msix_info = nbl_hw_cfg_msix_info,
	.flush_write = nbl_flush_writes,

	.update_mailbox_queue_tail_ptr = nbl_hw_update_mailbox_queue_tail_ptr,
	.config_mailbox_rxq = nbl_hw_config_mailbox_rxq,
	.config_mailbox_txq = nbl_hw_config_mailbox_txq,
	.stop_mailbox_rxq = nbl_hw_stop_mailbox_rxq,
	.stop_mailbox_txq = nbl_hw_stop_mailbox_txq,
	.get_host_pf_mask = nbl_hw_get_host_pf_mask,
	.get_real_bus = nbl_hw_get_real_bus,

	.cfg_mailbox_qinfo = nbl_hw_cfg_mailbox_qinfo,
	.set_mailbox_irq = nbl_hw_set_mailbox_irq,

	.get_fw_eth_map = nbl_hw_get_fw_eth_map,
	.get_board_info = nbl_hw_get_board_info,
};

/* Structure starts here, adding an op should not modify anything below */
static struct nbl_hw_mgt *nbl_hw_setup_hw_mgt(struct nbl_common_info *common)
{
	struct device *dev = common->dev;
	struct nbl_hw_mgt *hw_mgt;

	hw_mgt = devm_kzalloc(dev, sizeof(*hw_mgt), GFP_KERNEL);
	if (!hw_mgt)
		return ERR_PTR(-ENOMEM);

	hw_mgt->common = common;

	return hw_mgt;
}

static struct nbl_hw_ops_tbl *nbl_hw_setup_ops(struct nbl_common_info *common,
					       struct nbl_hw_mgt *hw_mgt)
{
	struct nbl_hw_ops_tbl *hw_ops_tbl;
	struct device *dev;

	dev = common->dev;
	hw_ops_tbl = devm_kzalloc(dev, sizeof(*hw_ops_tbl), GFP_KERNEL);
	if (!hw_ops_tbl)
		return ERR_PTR(-ENOMEM);
	if (!hw_ops.cfg_msix_map || !hw_ops.cfg_msix_info ||
	    !hw_ops.flush_write || !hw_ops.update_mailbox_queue_tail_ptr ||
	    !hw_ops.config_mailbox_rxq || !hw_ops.config_mailbox_txq ||
	    !hw_ops.stop_mailbox_rxq || !hw_ops.stop_mailbox_txq ||
	    !hw_ops.get_host_pf_mask || !hw_ops.get_real_bus ||
	    !hw_ops.cfg_mailbox_qinfo || !hw_ops.set_mailbox_irq ||
	    !hw_ops.get_fw_eth_map || !hw_ops.get_board_info ||
	    !hw_ops.init_module || !hw_ops.deinit_module)
		return ERR_PTR(-EINVAL);
	hw_ops_tbl->ops = &hw_ops;
	hw_ops_tbl->priv = hw_mgt;

	return hw_ops_tbl;
}

static int nbl_pcim_request_selected_bars(struct pci_dev *pdev, u32 mask,
					  const char *name)
{
	int bar;
	int ret;

	for (bar = 0; bar < PCI_STD_NUM_BARS; bar++) {
		if (!(mask & BIT(bar)))
			continue;
		ret = pcim_request_region(pdev, bar, name);
		if (ret)
			return ret;
	}
	return 0;
}

int nbl_hw_init_leonis(struct nbl_adapter *adapter)
{
	resource_size_t expect_sz = NBL_MEM_BAR_TOTAL_SIZE;
	struct nbl_common_info *common = &adapter->common;
	struct nbl_hw_ops_tbl *hw_ops_tbl = NULL;
	struct pci_dev *pdev = common->pdev;
	struct nbl_hw_mgt *hw_mgt = NULL;
	resource_size_t bar_len;
	resource_size_t hw_size;
	u32 bar_mask;
	int ret;

	hw_mgt = nbl_hw_setup_hw_mgt(common);
	if (IS_ERR(hw_mgt)) {
		ret = PTR_ERR(hw_mgt);
		goto setup_mgt_fail;
	}
	bar_mask = BIT(NBL_MEMORY_BAR) | BIT(NBL_MAILBOX_BAR);
	ret = nbl_pcim_request_selected_bars(pdev, bar_mask, NBL_DRIVER_NAME);
	if (ret) {
		dev_err(&pdev->dev,
			"Request memory bar failed, err = %d\n",
			ret);
		goto setup_mgt_fail;
	}

	bar_len = pci_resource_len(pdev, NBL_MEMORY_BAR);
	if (!(pci_resource_flags(pdev, NBL_MEMORY_BAR) & IORESOURCE_MEM)) {
		dev_err(&pdev->dev, "MEMORY BAR is not memory resource\n");
		ret = -EINVAL;
		goto setup_mgt_fail;
	}
	if (common->has_ctrl) {
		/*
		 * Hardware layout: MEMORY BAR total size is 64M.
		 * The tail NBL_RDMA_NOTIFY_LEN bytes of the 64M BAR are
		 * reserved exclusively for RDMA notify hardware.
		 * Ethernet driver must avoid mapping this reserved tail
		 * to prevent x86 PAT aliasing conflict between eth net
		 * mapping and RDMA driver WC mapping. Mapping starts
		 * at BAR offset 0.
		 *
		 * Skip trailing NBL_RDMA_NOTIFY_LEN bytes at BAR tail.
		 * Round size down to page boundary to avoid ioremap
		 * rounding up and accidentally including RDMA reserved
		 * region when PAGE_SIZE > 8KiB.
		 */
		if (bar_len < NBL_MEM_BAR_TOTAL_SIZE) {
			dev_err(&pdev->dev,
				"MEMORY BAR len %pa smaller than expected %pa\n",
				&bar_len, &expect_sz);
			ret = -EINVAL;
			goto setup_mgt_fail;
		}
		hw_size = PAGE_ALIGN_DOWN(NBL_MEM_BAR_TOTAL_SIZE -
					  NBL_RDMA_NOTIFY_LEN);
		hw_mgt->hw_addr =
			pcim_iomap(pdev, NBL_MEMORY_BAR,
				   hw_size);
	} else {
		if (bar_len < NBL_REG_NET_ONLY_LEN) {
			dev_err(&pdev->dev,
				"MEMORY BAR len %pa too small for net only reg space\n",
				&bar_len);
			ret = -EINVAL;
			goto setup_mgt_fail;
		}
		hw_size = NBL_REG_NET_ONLY_LEN;
		hw_mgt->hw_addr = pcim_iomap(pdev, NBL_MEMORY_BAR,
					     hw_size);
	}
	if (!hw_mgt->hw_addr) {
		dev_err(&pdev->dev, "MEMORY BAR pcim_iomap failed\n");
		ret = -EIO;
		goto setup_mgt_fail;
	}

	bar_len = pci_resource_len(pdev, NBL_MAILBOX_BAR);
	if (!(pci_resource_flags(pdev, NBL_MAILBOX_BAR) & IORESOURCE_MEM)) {
		dev_err(&pdev->dev, "MAILBOX BAR is not memory resource\n");
		ret = -EINVAL;
		goto setup_mgt_fail;
	}
	if (bar_len < NBL_BAR2_MAX_LEN) {
		dev_err(&pdev->dev, "MAILBOX BAR length %pa too small\n",
			&bar_len);
		ret = -EINVAL;
		goto setup_mgt_fail;
	}
	hw_mgt->mailbox_bar_hw_addr = pcim_iomap(pdev, NBL_MAILBOX_BAR,
						 bar_len);
	if (!hw_mgt->mailbox_bar_hw_addr) {
		dev_err(&pdev->dev, "MAILBOX BAR pcim_iomap failed\n");
		ret = -EIO;
		goto setup_mgt_fail;
	}

	hw_mgt->mailbox_bar_size = bar_len;
	spin_lock_init(&hw_mgt->reg_lock);

	hw_ops_tbl = nbl_hw_setup_ops(common, hw_mgt);
	if (IS_ERR(hw_ops_tbl)) {
		ret = PTR_ERR(hw_ops_tbl);
		goto setup_mgt_fail;
	}
	adapter->intf.hw_ops_tbl = hw_ops_tbl;
	adapter->core.hw_mgt = hw_mgt;

	return 0;

setup_mgt_fail:
	return ret;
}

void nbl_hw_remove_leonis(struct nbl_adapter *adapter)
{
	/* All BAR mappings & PCI regions are managed by pcim/devres,
	 * no manual iounmap / release required
	 */
}
