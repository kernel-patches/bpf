// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022, MediaTek Inc.
 */

#include <linux/acpi.h>
#include <linux/aer.h>
#include <linux/bitfield.h>
#include <linux/debugfs.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include "mtk_dev.h"
#include "mtk_trans_ctrl.h"
#include "mtk_pci.h"
#include "mtk_pci_reg.h"
#include "mtk_port.h"
#include "mtk_port_io.h"

#define MTK_PCI_TRANSPARENT_ATR_SIZE	(0x3F)
#define MTK_PCI_MINIMUM_ATR_SIZE	(0x1000)
#define ATR_SIZE_LO32_MASK		GENMASK_ULL(31, 0)
#define ATR_SIZE_HI32_MASK		GENMASK_ULL(63, 32)
#define ATR_SIZE_BIAS_FROM_LO32		2
#define ATR_ADDR_ALIGN_MASK		0xFFFFF000
#define ATR_EN				BIT(0)
#define ATR_PARAM_OFFSET		16
#define SET_HW_BITS(dest, chs, mhccif, dev)		\
	({						\
		if ((chs) & (dev))					\
			(dest) |= FIELD_PREP(mhccif, 1);		\
	})

struct mtk_mhccif_cb {
	struct list_head entry;
	int (*evt_cb)(u32 status, void *data);
	void *data;
	u32 chs;
};

/**
 * mtk_pci_setup_atr() - Configure a PCIe address translation rule
 * @mdev: MTK MD device
 * @cfg: ATR configuration parameters
 *
 * Return: 0 on success, negative error code on failure.
 */
int mtk_pci_setup_atr(struct mtk_md_dev *mdev, struct mtk_atr_cfg *cfg)
{
	struct mtk_pci_priv *priv = mdev->hw_priv;
	u32 addr, val, size_h, size_l;
	int atr_size, pos, offset;

	if (cfg->transparent) {
		/* No address conversion is performed */
		atr_size = MTK_PCI_TRANSPARENT_ATR_SIZE;
	} else {
		if (cfg->size < MTK_PCI_MINIMUM_ATR_SIZE)
			cfg->size = MTK_PCI_MINIMUM_ATR_SIZE;

		if (cfg->src_addr & (cfg->size - 1)) {
			dev_err(mdev->dev, "Invalid atr src addr is not aligned to size\n");
			return -EFAULT;
		}

		if (cfg->trsl_addr & (cfg->size - 1)) {
			dev_err(mdev->dev,
				"Invalid atr trsl addr is not aligned to size, %llx, %llx\n",
				cfg->trsl_addr, cfg->size - 1);
			return -EFAULT;
		}

		size_l = FIELD_GET(ATR_SIZE_LO32_MASK, cfg->size);
		size_h = FIELD_GET(ATR_SIZE_HI32_MASK, cfg->size);
		pos = ffs(size_l);
		if (pos) {
			atr_size = pos - ATR_SIZE_BIAS_FROM_LO32;
		} else {
			pos = ffs(size_h);
			atr_size = pos + 32 - ATR_SIZE_BIAS_FROM_LO32;
		}
	}

	/* Calculate table offset */
	offset = ATR_PORT_OFFSET * cfg->port + ATR_TABLE_OFFSET * cfg->table;

	addr = REG_ATR_PCIE_WIN0_T0_SRC_ADDR_MSB + offset;
	val = (u32)(cfg->src_addr >> 32);
	mtk_pci_mac_write32(priv, addr, val);

	addr = REG_ATR_PCIE_WIN0_T0_TRSL_ADDR_MSB + offset;
	val = (u32)(cfg->trsl_addr >> 32);
	mtk_pci_mac_write32(priv, addr, val);

	addr = REG_ATR_PCIE_WIN0_T0_TRSL_ADDR_LSB + offset;
	val = (u32)(cfg->trsl_addr & ATR_ADDR_ALIGN_MASK);
	mtk_pci_mac_write32(priv, addr, val);

	/* TRSL_PARAM */
	addr = REG_ATR_PCIE_WIN0_T0_TRSL_PARAM + offset;
	val = (cfg->trsl_param << ATR_PARAM_OFFSET) | cfg->trsl_id;
	mtk_pci_mac_write32(priv, addr, val);

	/* Enable ATR last, after translation target is fully programmed */
	addr = REG_ATR_PCIE_WIN0_T0_SRC_ADDR_LSB + offset;
	val = (u32)(cfg->src_addr & ATR_ADDR_ALIGN_MASK) | (atr_size << 1) | ATR_EN;
	mtk_pci_mac_write32(priv, addr, val);

	/* Ensure ATR is set */
	mtk_pci_mac_read32(priv, addr);

	return 0;
}

/**
 * mtk_pci_atr_disable() - Disable all PCIe address translation rules
 * @priv: MTK PCI private data
 */
void mtk_pci_atr_disable(struct mtk_pci_priv *priv)
{
	int port, tbl, offset;
	u32 val;

	/* Disable all ATR table for all ports */
	for (port = ATR_SRC_PCI_WIN0; port <= ATR_SRC_AXIS_3; port++)
		for (tbl = 0; tbl < ATR_TABLE_NUM_PER_ATR; tbl++) {
			/* Calculate table offset */
			offset = ATR_PORT_OFFSET * port + ATR_TABLE_OFFSET * tbl;
			val = mtk_pci_mac_read32(priv, REG_ATR_PCIE_WIN0_T0_SRC_ADDR_LSB + offset);
			val = val & (~BIT(0));
			/* Disable table by SRC_ADDR_L */
			mtk_pci_mac_write32(priv, REG_ATR_PCIE_WIN0_T0_SRC_ADDR_LSB + offset, val);
		}
}

/**
 * mtk_pci_get_dev_state() - Read the device state from the modem
 * @mdev: MTK MD device
 *
 * Return: Device state value.
 */
u32 mtk_pci_get_dev_state(struct mtk_md_dev *mdev)
{
	return mtk_pci_mac_read32(mdev->hw_priv, REG_PCIE_DEBUG_DUMMY_7);
}

/**
 * mtk_pci_ack_dev_state() - Acknowledge the device state to the modem
 * @mdev: MTK MD device
 * @state: State value to acknowledge
 */
void mtk_pci_ack_dev_state(struct mtk_md_dev *mdev, u32 state)
{
	mtk_pci_mac_write32(mdev->hw_priv, REG_PCIE_DEBUG_DUMMY_7, state);
}

/**
 * mtk_pci_get_irq_id() - Map an IRQ source to its hardware IRQ ID
 * @mdev: MTK MD device
 * @irq_src: IRQ source enum
 *
 * Return: IRQ ID on success, -EINVAL on failure.
 */
int mtk_pci_get_irq_id(struct mtk_md_dev *mdev, enum mtk_irq_src irq_src)
{
	struct mtk_pci_priv *priv = mdev->hw_priv;
	const int *irq_tbl = priv->cfg->irq_tbl;
	int irq_id = -EINVAL;

	if (irq_src > MTK_IRQ_SRC_MIN && irq_src < MTK_IRQ_SRC_MAX) {
		irq_id = irq_tbl[irq_src];
		if (irq_id < 0 || irq_id >= MTK_IRQ_CNT_MAX)
			irq_id = -EINVAL;
	}

	return irq_id;
}

/**
 * mtk_pci_get_virq_id() - Get the Linux virtual IRQ for a hardware IRQ ID
 * @mdev: MTK MD device
 * @irq_id: Hardware IRQ ID
 *
 * Return: Virtual IRQ number on success, negative error code on failure.
 */
int mtk_pci_get_virq_id(struct mtk_md_dev *mdev, int irq_id)
{
	struct pci_dev *pdev = to_pci_dev(mdev->dev);
	struct mtk_pci_priv *priv = mdev->hw_priv;

	if (irq_id < 0 || irq_id >= priv->irq_cnt)
		return -EINVAL;

	return pci_irq_vector(pdev, irq_id);
}

/**
 * mtk_pci_register_irq() - Register a callback for a hardware IRQ
 * @mdev: MTK MD device
 * @irq_id: Hardware IRQ ID
 * @irq_cb: Callback function
 * @data: Private data passed to callback
 *
 * Return: 0 on success, negative error code on failure.
 */
int mtk_pci_register_irq(struct mtk_md_dev *mdev, int irq_id,
			 int (*irq_cb)(int irq_id, void *data), void *data)
{
	struct mtk_pci_priv *priv = mdev->hw_priv;

	if ((irq_id < 0 || irq_id >= MTK_IRQ_CNT_MAX) || !irq_cb)
		return -EINVAL;

	spin_lock(&priv->irq_cb_lock);
	if (priv->irq_cb_list[irq_id]) {
		spin_unlock(&priv->irq_cb_lock);
		dev_err(mdev->dev,
			"Unable to register irq, irq_id=%d, it's already been register by %ps.\n",
			irq_id, priv->irq_cb_list[irq_id]);
		return -EFAULT;
	}
	priv->irq_cb_data[irq_id] = data;
	smp_wmb(); /* Ensure data is visible before callback */
	WRITE_ONCE(priv->irq_cb_list[irq_id], irq_cb);
	spin_unlock(&priv->irq_cb_lock);

	return 0;
}

/**
 * mtk_pci_unregister_irq() - Unregister a hardware IRQ callback
 * @mdev: MTK MD device
 * @irq_id: Hardware IRQ ID
 *
 * Return: 0 on success, negative error code on failure.
 */
int mtk_pci_unregister_irq(struct mtk_md_dev *mdev, int irq_id)
{
	struct mtk_pci_priv *priv = mdev->hw_priv;
	int virq_id;

	if (irq_id < 0 || irq_id >= MTK_IRQ_CNT_MAX)
		return -EINVAL;

	if (!READ_ONCE(priv->irq_cb_list[irq_id])) {
		dev_err(mdev->dev, "irq_id=%d has not been registered\n", irq_id);
		return -EFAULT;
	}

	/* Stop the source and wait for in-flight handlers
	 * before the callback or its data can disappear.
	 */
	mtk_pci_mask_irq(mdev, irq_id);
	virq_id = mtk_pci_get_virq_id(mdev, irq_id);
	if (virq_id >= 0)
		synchronize_irq(virq_id);

	spin_lock(&priv->irq_cb_lock);
	WRITE_ONCE(priv->irq_cb_list[irq_id], NULL);
	priv->irq_cb_data[irq_id] = NULL;
	spin_unlock(&priv->irq_cb_lock);

	return 0;
}

/**
 * mtk_pci_mask_irq() - Mask (disable) a hardware IRQ
 * @mdev: MTK MD device
 * @irq_id: Hardware IRQ ID
 *
 * Return: 0 on success, negative error code on failure.
 */
int mtk_pci_mask_irq(struct mtk_md_dev *mdev, int irq_id)
{
	struct mtk_pci_priv *priv = mdev->hw_priv;

	if (irq_id < 0 || irq_id >= MTK_IRQ_CNT_MAX ||
	    priv->irq_type != PCI_IRQ_MSIX) {
		dev_err(mdev->dev, "Failed to mask irq: input irq_id=%d\n", irq_id);
		return -EINVAL;
	}

	mtk_pci_mac_write32(priv, REG_IMASK_HOST_MSIX_CLR_GRP0_0, BIT(irq_id));

	return 0;
}

/**
 * mtk_pci_unmask_irq() - Unmask (enable) a hardware IRQ
 * @mdev: MTK MD device
 * @irq_id: Hardware IRQ ID
 *
 * Return: 0 on success, negative error code on failure.
 */
int mtk_pci_unmask_irq(struct mtk_md_dev *mdev, int irq_id)
{
	struct mtk_pci_priv *priv = mdev->hw_priv;

	if (irq_id < 0 || irq_id >= MTK_IRQ_CNT_MAX ||
	    priv->irq_type != PCI_IRQ_MSIX) {
		dev_err(mdev->dev, "Failed to unmask irq: input irq_id=%d\n", irq_id);
		return -EINVAL;
	}

	mtk_pci_mac_write32(priv, REG_IMASK_HOST_MSIX_SET_GRP0_0, BIT(irq_id));

	return 0;
}

/**
 * mtk_pci_clear_irq() - Clear (acknowledge) a hardware IRQ
 * @mdev: MTK MD device
 * @irq_id: Hardware IRQ ID
 *
 * Return: 0 on success, negative error code on failure.
 */
int mtk_pci_clear_irq(struct mtk_md_dev *mdev, int irq_id)
{
	struct mtk_pci_priv *priv = mdev->hw_priv;

	if (irq_id < 0 || irq_id >= MTK_IRQ_CNT_MAX ||
	    priv->irq_type != PCI_IRQ_MSIX) {
		dev_err(mdev->dev, "Failed to clear irq: input irq_id=%d\n", irq_id);
		return -EINVAL;
	}

	mtk_pci_mac_write32(priv, REG_MSIX_ISTATUS_HOST_GRP0_0, BIT(irq_id));

	return 0;
}

static u32 mtk_pci_ext_d2h_evt_hw_bits(u32 chs)
{
	u32 hw_bits = 0;

	SET_HW_BITS(hw_bits, chs, MHCCIF_EP2RC_EVT_BOOT_FLOW_SYNC,
		    DEV_EVT_D2H_BOOT_FLOW_SYNC);
	SET_HW_BITS(hw_bits, chs, MHCCIF_EP2RC_EVT_ASYNC_HS_NOTIFY_SAP,
		    DEV_EVT_D2H_ASYNC_HS_NOTIFY_SAP);
	SET_HW_BITS(hw_bits, chs, MHCCIF_EP2RC_EVT_ASYNC_HS_NOTIFY_MD,
		    DEV_EVT_D2H_ASYNC_HS_NOTIFY_MD);

	return hw_bits;
}

static u32 mtk_pci_ext_d2h_evt_chs(u32 hw_bits)
{
	u32 chs = 0;

	if (!hw_bits)
		return chs;

	chs = FIELD_PREP(DEV_EVT_D2H_BOOT_FLOW_SYNC,
			 FIELD_GET(MHCCIF_EP2RC_EVT_BOOT_FLOW_SYNC, hw_bits)) |
	      FIELD_PREP(DEV_EVT_D2H_ASYNC_HS_NOTIFY_SAP,
			 FIELD_GET(MHCCIF_EP2RC_EVT_ASYNC_HS_NOTIFY_SAP, hw_bits)) |
	      FIELD_PREP(DEV_EVT_D2H_ASYNC_HS_NOTIFY_MD,
			 FIELD_GET(MHCCIF_EP2RC_EVT_ASYNC_HS_NOTIFY_MD, hw_bits));

	return chs;
}

/**
 * mtk_pci_register_ext_evt() - Register a callback for MHCCIF device events
 * @mdev: MTK MD device
 * @chs: Bitmask of event channels to register
 * @evt_cb: Callback function
 * @data: Private data passed to callback
 *
 * Return: 0 on success, negative error code on failure.
 */
int mtk_pci_register_ext_evt(struct mtk_md_dev *mdev, u32 chs,
			     int (*evt_cb)(u32 status, void *data), void *data)
{
	struct mtk_pci_priv *priv = mdev->hw_priv;
	struct mtk_mhccif_cb *cb;
	int ret = 0;

	if (!chs || !evt_cb)
		return -EINVAL;

	spin_lock_bh(&priv->mhccif_lock);
	list_for_each_entry(cb, &priv->mhccif_cb_list, entry) {
		if (cb->chs & chs) {
			ret = -EFAULT;
			dev_err(mdev->dev,
				"Unable to register evt, intersection: chs=0x%08x&0x%08x cb=%ps\n",
				chs, cb->chs, cb->evt_cb);
			goto err_spin_unlock;
		}
	}
	cb = kzalloc(sizeof(*cb), GFP_ATOMIC);
	if (!cb) {
		ret = -ENOMEM;
		goto err_spin_unlock;
	}
	cb->evt_cb = evt_cb;
	cb->data = data;
	cb->chs = chs;
	list_add_tail(&cb->entry, &priv->mhccif_cb_list);
err_spin_unlock:
	spin_unlock_bh(&priv->mhccif_lock);

	return ret;
}

/**
 * mtk_pci_unregister_ext_evt() - Unregister an MHCCIF device event callback
 * @mdev: MTK MD device
 * @chs: Bitmask of event channels to unregister
 */
void mtk_pci_unregister_ext_evt(struct mtk_md_dev *mdev, u32 chs)
{
	struct mtk_pci_priv *priv = mdev->hw_priv;
	struct mtk_mhccif_cb *cb, *next;

	if (!chs)
		return;

	spin_lock_bh(&priv->mhccif_lock);
	list_for_each_entry_safe(cb, next, &priv->mhccif_cb_list, entry) {
		if (cb->chs == chs) {
			list_del(&cb->entry);
			kfree(cb);
			goto out;
		}
	}
	dev_warn(mdev->dev,
		 "Unable to unregister evt, no chs=0x%08x has been registered.\n", chs);
out:
	spin_unlock_bh(&priv->mhccif_lock);
}

/**
 * mtk_pci_mask_ext_evt() - Mask (disable) MHCCIF device events
 * @mdev: MTK MD device
 * @chs: Bitmask of event channels to mask
 */
void mtk_pci_mask_ext_evt(struct mtk_md_dev *mdev, u32 chs)
{
	struct mtk_pci_priv *priv = mdev->hw_priv;
	u32 hw_bits = mtk_pci_ext_d2h_evt_hw_bits(chs);

	mtk_pci_write32(mdev, priv->cfg->mhccif_rc_base_addr +
			MHCCIF_EP2RC_SW_INT_EAP_MASK_SET, hw_bits);
}

/**
 * mtk_pci_unmask_ext_evt() - Unmask (enable) MHCCIF device events
 * @mdev: MTK MD device
 * @chs: Bitmask of event channels to unmask
 */
void mtk_pci_unmask_ext_evt(struct mtk_md_dev *mdev, u32 chs)
{
	struct mtk_pci_priv *priv = mdev->hw_priv;
	u32 hw_bits = mtk_pci_ext_d2h_evt_hw_bits(chs);

	mtk_pci_write32(mdev, priv->cfg->mhccif_rc_base_addr +
			MHCCIF_EP2RC_SW_INT_EAP_MASK_CLR, hw_bits);
}

/**
 * mtk_pci_clear_ext_evt() - Clear (acknowledge) MHCCIF device events
 * @mdev: MTK MD device
 * @chs: Bitmask of event channels to clear
 */
void mtk_pci_clear_ext_evt(struct mtk_md_dev *mdev, u32 chs)
{
	struct mtk_pci_priv *priv = mdev->hw_priv;
	u32 hw_bits = mtk_pci_ext_d2h_evt_hw_bits(chs);

	mtk_pci_write32(mdev, priv->cfg->mhccif_rc_base_addr +
			MHCCIF_EP2RC_SW_INT_ACK, hw_bits);
}

static u32 mtk_pci_ext_h2d_evt_hw_bits(u32 chs)
{
	u32 hw_bits = 0;

	SET_HW_BITS(hw_bits, chs, MHCCIF_RC2EP_EVT_DEVICE_RESET,
		    DEV_EVT_H2D_DEVICE_RESET);
	return hw_bits;
}

/**
 * mtk_pci_send_ext_evt() - Send an MHCCIF event to the modem
 * @mdev: MTK MD device
 * @ch: Event channel to trigger (must be a single bit)
 *
 * Return: 0 on success, negative error code on failure.
 */
int mtk_pci_send_ext_evt(struct mtk_md_dev *mdev, u32 ch)
{
	struct mtk_pci_priv *priv = mdev->hw_priv;
	u32 rc_base, hw_bits;

	rc_base = priv->cfg->mhccif_rc_base_addr;

	/* Only allow one ch to be triggered at a time */
	if (!is_power_of_2(ch)) {
		dev_err(mdev->dev, "Unsupported ext evt ch=0x%08x\n", ch);
		return -EINVAL;
	}

	hw_bits = mtk_pci_ext_h2d_evt_hw_bits(ch);
	if (!hw_bits) {
		dev_err(mdev->dev, "Unmapped ext evt ch=0x%08x\n", ch);
		return -EINVAL;
	}

	mtk_pci_write32(mdev, rc_base + MHCCIF_RC2EP_SW_BSY, hw_bits);
	mtk_pci_write32(mdev, rc_base + MHCCIF_RC2EP_SW_TCHNUM, ffs(hw_bits) - 1);
	return 0;
}

static u32 mtk_pci_get_ext_evt_hw_status(struct mtk_md_dev *mdev)
{
	struct mtk_pci_priv *priv = mdev->hw_priv;

	return mtk_pci_read32(mdev, priv->cfg->mhccif_rc_base_addr +
			      MHCCIF_EP2RC_SW_INT_STS);
}

static void mtk_pci_ack_ext_evt_hw(struct mtk_md_dev *mdev, u32 hw_bits)
{
	struct mtk_pci_priv *priv = mdev->hw_priv;

	mtk_pci_write32(mdev, priv->cfg->mhccif_rc_base_addr +
			MHCCIF_EP2RC_SW_INT_ACK, hw_bits);
	/* Ensure the ack lands before level 1 is cleared */
	mtk_pci_read32(mdev, priv->cfg->mhccif_rc_base_addr +
		       MHCCIF_EP2RC_SW_INT_STS);
}

/**
 * mtk_pci_pldr() - Reset the modem via its ACPI MRST._RST method
 * @mdev: MTK MD device
 *
 * Return:
 * * 0       - Success, device was reset.
 * * -ENODEV - No ACPI, no handle or no MRST._RST method.  Device
 *             untouched.
 * * -EIO    - MRST._RST failed.  Device untouched, still running;
 *             a different reset may be attempted.
 */
int mtk_pci_pldr(struct mtk_md_dev *mdev)
{
	struct acpi_buffer buffer = { ACPI_ALLOCATE_BUFFER, NULL };
	acpi_status acpi_ret;
	acpi_handle handle;

	if (acpi_disabled) {
		dev_err(mdev->dev, "Unsupported, acpi function isn't enable\n");
		return -ENODEV;
	}

	handle = ACPI_HANDLE(mdev->dev);
	if (!handle) {
		dev_err(mdev->dev, "Unsupported, acpi handle isn't found\n");
		return -ENODEV;
	}
	if (!acpi_has_method(handle, "MRST._RST")) {
		dev_err(mdev->dev, "Unsupported, pldr method isn't supported\n");
		return -ENODEV;
	}
	acpi_ret = acpi_evaluate_object(handle, "MRST._RST", NULL, &buffer);
	if (ACPI_FAILURE(acpi_ret)) {
		dev_err(mdev->dev, "Failed to execute MRST._RST method: %s\n",
			acpi_format_exception(acpi_ret));
		return -EIO;
	}
	acpi_os_free(buffer.pointer);

	return 0;
}

/**
 * mtk_pci_get_dev_cfg() - Read the device configuration from the modem
 * @mdev: MTK MD device
 *
 * Return: Device configuration value.
 */
u32 mtk_pci_get_dev_cfg(struct mtk_md_dev *mdev)
{
	u32 val;

	val = mtk_pci_mac_read32(mdev->hw_priv, REG_PCIE_DEBUG_DUMMY_4);
	return (val >> MTK_CFG_INFO_BIT_SHIFT);
}

/**
 * mtk_pci_link_check() - Check if the PCIe link to the modem is active
 * @mdev: MTK MD device
 *
 * Return: true if the device is present, false otherwise.
 */
bool mtk_pci_link_check(struct mtk_md_dev *mdev)
{
	return pci_device_is_present(to_pci_dev(mdev->dev));
}

static void mtk_mhccif_isr_work(struct work_struct *work)
{
	struct mtk_pci_priv *priv =
		container_of(work, struct mtk_pci_priv, mhccif_work);
	struct mtk_md_dev *mdev = priv->irq_desc->mdev;
	struct mtk_mhccif_cb *cb;
	u32 stat, mask, chs;

	stat = mtk_pci_get_ext_evt_hw_status(mdev);
	mask = mtk_pci_read32(mdev, priv->cfg->mhccif_rc_base_addr
		+ MHCCIF_EP2RC_SW_INT_EAP_MASK);
	if (unlikely(stat == U32_MAX && !(mtk_pci_link_check(mdev)))) {
		/* When link failed, we don't need to unmask/clear. */
		dev_err(mdev->dev, "Failed to check link in MHCCIF handler.\n");
		return;
	}

	stat &= ~mask;
	/* Acknowledge level 2 before dispatch: an event that re-asserts
	 * while a callback runs must survive as a new status bit.
	 */
	if (stat)
		mtk_pci_ack_ext_evt_hw(mdev, stat);

	chs = mtk_pci_ext_d2h_evt_chs(stat);
	/* Callbacks must not sleep or modify mhccif_cb_list */
	spin_lock_bh(&priv->mhccif_lock);
	list_for_each_entry(cb, &priv->mhccif_cb_list, entry) {
		if (cb->chs & chs)
			cb->evt_cb(cb->chs & chs, cb->data);
	}
	spin_unlock_bh(&priv->mhccif_lock);

	mtk_pci_clear_irq(mdev, priv->mhccif_irq_id);
	mtk_pci_unmask_irq(mdev, priv->mhccif_irq_id);
}

static const struct  pci_device_id t9xx_pci_table[] = {
	MTK_PCI_DEV_CFG(0x0900, mtk_dev_cfg_0900),
	CEI_PCI_DEV_CFG(0x01CA, mtk_dev_cfg_0900),
	{/* end: all zeroes */}
};

MODULE_DEVICE_TABLE(pci, t9xx_pci_table);

static int mtk_pci_bar_init(struct mtk_md_dev *mdev)
{
	struct pci_dev *pdev = to_pci_dev(mdev->dev);
	struct mtk_pci_priv *priv = mdev->hw_priv;

	priv->mac_reg_base = pcim_iomap_region(pdev, MTK_BAR_0_1_IDX,
					       mdev->dev_str);
	if (IS_ERR(priv->mac_reg_base)) {
		dev_err(mdev->dev, "Failed to map BAR0/1\n");
		return PTR_ERR(priv->mac_reg_base);
	}

	priv->bar23_addr = pcim_iomap_region(pdev, MTK_BAR_2_3_IDX,
					     mdev->dev_str);
	if (IS_ERR(priv->bar23_addr)) {
		dev_err(mdev->dev, "Failed to map BAR2/3\n");
		return PTR_ERR(priv->bar23_addr);
	}

	/* We use MD view base address "0" to observe registers */
	priv->ext_reg_base = priv->bar23_addr - ATR_PCIE_REG_TRSL_ADDR;

	return 0;
}

static int mtk_mhccif_irq_cb(int irq_id, void *data)
{
	struct mtk_md_dev *mdev = data;
	struct mtk_pci_priv *priv;

	priv = mdev->hw_priv;
	queue_work(system_highpri_wq, &priv->mhccif_work);

	return 0;
}

static int mtk_mhccif_init(struct mtk_md_dev *mdev)
{
	struct mtk_pci_priv *priv = mdev->hw_priv;
	int ret;

	INIT_LIST_HEAD(&priv->mhccif_cb_list);
	spin_lock_init(&priv->mhccif_lock);
	INIT_WORK(&priv->mhccif_work, mtk_mhccif_isr_work);

	/* The write below goes through the BAR 2/3 ATR window, so this
	 * function must run after priv->cfg->atr_init().
	 * Mask every channel; consumers unmask the channels they need.
	 * Do NOT ack here: EP2RC status bits are latched one-shot
	 * notifications (e.g. BOOT_FLOW_SYNC raised before the driver
	 * loads) that the device never re-sends.  Masking blocks
	 * delivery but preserves the bit for delivery on unmask; an
	 * ack would erase it and the boot flow would hang silently.
	 */
	mtk_pci_write32(mdev, priv->cfg->mhccif_rc_base_addr +
			MHCCIF_EP2RC_SW_INT_EAP_MASK_SET, U32_MAX);

	ret = mtk_pci_get_irq_id(mdev, MTK_IRQ_SRC_MHCCIF);
	if (ret < 0) {
		dev_err(mdev->dev, "Failed to get mhccif_irq_id. ret=%d\n", ret);
		return ret;
	}
	priv->mhccif_irq_id = ret;

	ret = mtk_pci_register_irq(mdev, priv->mhccif_irq_id, mtk_mhccif_irq_cb, mdev);
	if (ret) {
		dev_err(mdev->dev, "Failed to register mhccif_irq callback\n");
		return ret;
	}

	return 0;
}

static void mtk_mhccif_exit(struct mtk_md_dev *mdev)
{
	struct mtk_pci_priv *priv = mdev->hw_priv;
	struct mtk_mhccif_cb *cb, *tmp;

	mtk_pci_unregister_irq(mdev, priv->mhccif_irq_id);
	cancel_work_sync(&priv->mhccif_work);

	list_for_each_entry_safe(cb, tmp, &priv->mhccif_cb_list, entry) {
		list_del(&cb->entry);
		kfree(cb);
	}
}

static irqreturn_t mtk_pci_irq_handler(struct mtk_md_dev *mdev, u32 irq_state)
{
	struct mtk_pci_priv *priv = mdev->hw_priv;
	int irq_id;

	/* Check whether each set bit has a callback, if has, call it */
	do {
		int (*cb)(int irq_id, void *data);

		irq_id = fls(irq_state) - 1;
		irq_state &= ~BIT(irq_id);
		cb = READ_ONCE(priv->irq_cb_list[irq_id]);
		if (likely(cb)) {
			smp_rmb(); /* Ensure data is read after callback */
			cb(irq_id, priv->irq_cb_data[irq_id]);
		} else {
			dev_err_ratelimited(mdev->dev,
					    "Unhandled irq_id=%d, no callback for it.\n",
					    irq_id);
			mtk_pci_clear_irq(mdev, irq_id);
		}
	} while (irq_state);

	return IRQ_HANDLED;
}

static irqreturn_t mtk_pci_irq_msix(int irq, void *data)
{
	struct mtk_pci_irq_desc *irq_desc = data;
	struct mtk_md_dev *mdev = irq_desc->mdev;
	struct mtk_pci_priv *priv;
	u32 irq_state, irq_enable;

	priv = mdev->hw_priv;
	irq_state = mtk_pci_mac_read32(priv, REG_MSIX_ISTATUS_HOST_GRP0_0);
	irq_enable = mtk_pci_mac_read32(priv, REG_IMASK_HOST_MSIX_GRP0_0);
	irq_state &= irq_enable;

	if (unlikely(irq_state == U32_MAX && irq_enable == U32_MAX))
		return IRQ_NONE; /* device gone */

	irq_state &= irq_desc->msix_bits; /* scope to this vector */
	if (unlikely(!irq_state))
		return IRQ_NONE;

	/* Mask the bit; the consumer unmasks it when it is done */
	mtk_pci_mac_write32(priv, REG_IMASK_HOST_MSIX_CLR_GRP0_0, irq_state);

	return mtk_pci_irq_handler(mdev, irq_state);
}

static int mtk_pci_request_irq_msix(struct mtk_md_dev *mdev)
{
	struct mtk_pci_priv *priv = mdev->hw_priv;
	struct mtk_pci_irq_desc *irq_desc;
	struct pci_dev *pdev;
	int ret, i;

	pdev = to_pci_dev(mdev->dev);
	irq_desc = priv->irq_desc;

	priv->irq_cnt = MTK_IRQ_CNT_MAX;
	priv->irq_type = PCI_IRQ_MSIX;

	for (i = 0; i < MTK_IRQ_CNT_MAX; i++) {
		irq_desc[i].mdev = mdev;
		irq_desc[i].msix_bits = BIT(i);
		snprintf(irq_desc[i].name, MTK_IRQ_NAME_LEN, "msix%d-%s", i, mdev->dev_str);
		ret = pci_request_irq(pdev, i, mtk_pci_irq_msix, NULL,
				      &irq_desc[i], "%s", irq_desc[i].name);
		if (ret) {
			dev_err(mdev->dev, "Failed to request %s: ret=%d\n",
				irq_desc[i].name, ret);
			for (i--; i >= 0; i--)
				pci_free_irq(pdev, i, &irq_desc[i]);
			priv->irq_cnt = 0;
			priv->irq_type = 0;
			return ret;
		}
	}

	return 0;
}

static int mtk_pci_request_irq(struct mtk_md_dev *mdev)
{
	struct pci_dev *pdev = to_pci_dev(mdev->dev);
	int ret;

	ret = pci_alloc_irq_vectors(pdev, MTK_IRQ_CNT_MAX,
				    MTK_IRQ_CNT_MAX, PCI_IRQ_MSIX);
	if (ret < 0) {
		dev_err(mdev->dev,
			"Unable to alloc %d MSI-X vectors: ret=%d\n",
			MTK_IRQ_CNT_MAX, ret);
		return ret;
	}

	ret = mtk_pci_request_irq_msix(mdev);
	if (ret)
		pci_free_irq_vectors(pdev);

	return ret;
}

static void mtk_pci_free_irq(struct mtk_md_dev *mdev)
{
	struct pci_dev *pdev = to_pci_dev(mdev->dev);
	struct mtk_pci_priv *priv = mdev->hw_priv;
	int i;

	for (i = 0; i < priv->irq_cnt; i++)
		pci_free_irq(pdev, i, &priv->irq_desc[i]);

	pci_free_irq_vectors(pdev);
}

static int mtk_pci_dev_init(struct mtk_md_dev *mdev)
{
	int ret;

	ret = mtk_trans_ctrl_init(mdev);
	if (ret) {
		dev_err(mdev->dev, "Failed to initialize control plane: %d\n", ret);
		return ret;
	}

	return 0;
}

static void mtk_pci_dev_exit(struct mtk_md_dev *mdev)
{
	mtk_trans_ctrl_exit(mdev);
}

static int mtk_pci_dev_start(struct mtk_md_dev *mdev)
{
	return 0;
}
static const struct mtk_dev_ops pci_hw_ops = {
	.get_dev_state = mtk_pci_get_dev_state,
	.ack_dev_state = mtk_pci_ack_dev_state,
	.get_dev_cfg = mtk_pci_get_dev_cfg,
	.register_dev_evt = mtk_pci_register_ext_evt,
	.unregister_dev_evt = mtk_pci_unregister_ext_evt,
	.mask_dev_evt = mtk_pci_mask_ext_evt,
	.unmask_dev_evt = mtk_pci_unmask_ext_evt,
	.clear_dev_evt = mtk_pci_clear_ext_evt,
	.send_dev_evt = mtk_pci_send_ext_evt,
};

static int mtk_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct device *dev = &pdev->dev;
	struct mtk_pci_priv *priv;
	struct mtk_md_dev *mdev;
	int ret;

	mdev = devm_kzalloc(dev, sizeof(*mdev), GFP_KERNEL);
	if (!mdev) {
		ret = -ENOMEM;
		goto log_err;
	}
	mdev->dev_ops = &pci_hw_ops;
	mdev->dev = dev;

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv) {
		ret = -ENOMEM;
		goto log_err;
	}

	pci_set_drvdata(pdev, mdev);
	priv->cfg = (void *)id->driver_data;
	priv->mdev = mdev;
	mdev->hw_ver  = pdev->device;
	mdev->hw_priv = priv;
	mdev->dev     = dev;
	snprintf(mdev->dev_str, MTK_DEV_STR_LEN, "%02x%02x%d",
		 pdev->bus->number, PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));
	if (pdev->state_saved)
		pci_restore_state(pdev);

	ret = pcim_enable_device(pdev);
	if (ret) {
		dev_err(mdev->dev, "Failed to enable pci device.\n");
		goto log_err;
	}

	ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
	if (ret) {
		dev_err(mdev->dev, "Failed to set DMA Mask and Coherent. (ret=%d)\n", ret);
		goto log_err;
	}

	ret = mtk_pci_bar_init(mdev);
	if (ret)
		goto log_err;

	ret = priv->cfg->atr_init(mdev);
	if (ret)
		goto log_err;

	spin_lock_init(&priv->irq_cb_lock);

	ret = mtk_mhccif_init(mdev);
	if (ret)
		goto log_err;

	/* Mask every source before the handlers go in, so a source
	 * left enabled by firmware or a previous bind cannot fire
	 * into a half-initialised driver.
	 */
	mtk_pci_mac_write32(priv, REG_IMASK_HOST_MSIX_CLR_GRP0_0, U32_MAX);

	ret = mtk_pci_request_irq(mdev);
	if (ret)
		goto free_mhccif;

	ret = mtk_pci_dev_init(mdev);
	if (ret) {
		dev_err(mdev->dev, "Failed to init dev.\n");
		goto free_irq;
	}

	pci_set_master(pdev);
	mtk_pci_unmask_irq(mdev, priv->mhccif_irq_id);

	if (!mtk_pci_link_check(mdev)) {
		ret = -ENOLINK;
		goto clear_master;
	}

	ret = pci_save_state(pdev);
	if (ret) {
		dev_err(mdev->dev, "Failed to save PCI state: %d\n", ret);
		goto clear_master;
	}

	priv->saved_state = pci_store_saved_state(pdev);
	if (!priv->saved_state) {
		ret = -ENOMEM;
		goto clear_master;
	}

	ret = mtk_pci_dev_start(mdev);
	if (ret) {
		dev_err(mdev->dev, "Failed to start dev.\n");
		goto free_saved_state;
	}

	return 0;

free_saved_state:
	pci_load_and_free_saved_state(pdev, &priv->saved_state);
clear_master:
	pci_clear_master(pdev);
	mtk_pci_dev_exit(mdev);
free_irq:
	mtk_pci_free_irq(mdev);
free_mhccif:
	mtk_mhccif_exit(mdev);
log_err:
	dev_err(dev, "Failed to probe device, ret=%d\n", ret);

	return ret;
}

static void mtk_pci_remove(struct pci_dev *pdev)
{
	struct mtk_md_dev *mdev = pci_get_drvdata(pdev);
	struct mtk_pci_priv *priv = mdev->hw_priv;
	struct device *dev = &pdev->dev;
	int ret;

	mtk_pci_dev_exit(mdev);

	/* Silence every source before tearing anything down. */
	mtk_pci_mac_write32(priv, REG_IMASK_HOST_MSIX_CLR_GRP0_0, U32_MAX);

	/* Unregisters the callback (masks and synchronises the vector),
	 * then cancels the work.  With the callback gone the work cannot
	 * be requeued.
	 */
	mtk_mhccif_exit(mdev);
	mtk_pci_free_irq(mdev);
	pci_clear_master(pdev);

	/* Reset last: the endpoint comes back at power-on defaults,
	 * so no MMIO, config write or MSI-X teardown may follow it.
	 */
	ret = mtk_pci_pldr(mdev);
	if (ret && mtk_pci_link_check(mdev)) {
		dev_warn(dev, "PLDR failed (%d), trying MHCCIF reset\n", ret);
		if (mtk_pci_send_ext_evt(mdev, DEV_EVT_H2D_DEVICE_RESET))
			dev_err(dev, "MHCCIF reset failed\n");
	}

	pci_load_and_free_saved_state(pdev, &priv->saved_state);
}

static pci_ers_result_t mtk_pci_error_detected(struct pci_dev *pdev,
					       pci_channel_state_t state)
{
	struct mtk_md_dev *mdev = pci_get_drvdata(pdev);

	dev_err(mdev->dev, "AER detected: pci_channel_state_t=%d\n", state);

	/* AER recovery not supported, disconnect the device */
	return PCI_ERS_RESULT_DISCONNECT;
}

static const struct pci_error_handlers mtk_pci_err_handler = {
	.error_detected = mtk_pci_error_detected,
};

static struct pci_driver mtk_pci_drv = {
	.name = "mtk_pci_drv",
	.id_table = t9xx_pci_table,
	.probe = mtk_pci_probe,
	.remove = mtk_pci_remove,
	.err_handler = &mtk_pci_err_handler
};

module_pci_driver(mtk_pci_drv);

MODULE_DESCRIPTION("MediaTek T9xx PCIe WWAN driver pcie layer");
MODULE_LICENSE("GPL");
