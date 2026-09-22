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
	.flush_write = nbl_flush_writes,

	.update_mailbox_queue_tail_ptr = nbl_hw_update_mailbox_queue_tail_ptr,
	.config_mailbox_rxq = nbl_hw_config_mailbox_rxq,
	.config_mailbox_txq = nbl_hw_config_mailbox_txq,
	.stop_mailbox_rxq = nbl_hw_stop_mailbox_rxq,
	.stop_mailbox_txq = nbl_hw_stop_mailbox_txq,
	.get_host_pf_mask = nbl_hw_get_host_pf_mask,
	.get_real_bus = nbl_hw_get_real_bus,

	.cfg_mailbox_qinfo = nbl_hw_cfg_mailbox_qinfo,

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
	if (!hw_ops.flush_write || !hw_ops.update_mailbox_queue_tail_ptr ||
	    !hw_ops.config_mailbox_rxq || !hw_ops.config_mailbox_txq ||
	    !hw_ops.stop_mailbox_rxq || !hw_ops.stop_mailbox_txq ||
	    !hw_ops.get_host_pf_mask || !hw_ops.get_real_bus ||
	    !hw_ops.cfg_mailbox_qinfo ||
	    !hw_ops.get_fw_eth_map || !hw_ops.get_board_info)
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
