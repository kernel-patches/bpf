/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (c) 2022, MediaTek Inc.
 */

#ifndef __MTK_PCI_H__
#define __MTK_PCI_H__

#include <linux/pci.h>

#include "../mtk_dev.h"

enum mtk_irq_src {
	MTK_IRQ_SRC_MIN,
	MTK_IRQ_SRC_MHCCIF,
	MTK_IRQ_SRC_DPMAIF,
	MTK_IRQ_SRC_DPMAIF2,
	MTK_IRQ_SRC_CLDMA0,
	MTK_IRQ_SRC_CLDMA1,
	MTK_IRQ_SRC_CLDMA2,
	MTK_IRQ_SRC_CLDMA3,
	MTK_IRQ_SRC_PM_LOCK,
	MTK_IRQ_SRC_DPMAIF3,
	MTK_IRQ_SRC_DPMAIF6,
	MTK_IRQ_SRC_MAX
};

enum mtk_atr_src_port {
	ATR_SRC_PCI_WIN0 = 0,
	ATR_SRC_PCI_WIN1,
	ATR_SRC_AXIS_0,
	ATR_SRC_AXIS_1,
	ATR_SRC_AXIS_2,
	ATR_SRC_AXIS_3,
};

enum mtk_atr_dst_port {
	ATR_DST_PCI_TRX = 0,
	ATR_DST_AXIM_0 = 4,
	ATR_DST_AXIM_1,
	ATR_DST_AXIM_2,
	ATR_DST_AXIM_3,
};

#define MTK_PCI_CLASS                 0x0D4000
#define MTK_PCI_VENDOR_ID             0x14C3
#define CEI_PCI_VENDOR_ID             0x03F0

#define MTK_CFG_INFO_BIT_SHIFT        4

#define MTK_PCI_DEV_CFG(id, cfg) \
{ \
	PCI_DEVICE(MTK_PCI_VENDOR_ID, id), \
	MTK_PCI_CLASS, PCI_ANY_ID, \
	.driver_data = (kernel_ulong_t)&(cfg), \
}

#define CEI_PCI_DEV_CFG(id, cfg) \
{ \
	PCI_DEVICE(CEI_PCI_VENDOR_ID, id), \
	MTK_PCI_CLASS, PCI_ANY_ID, \
	.driver_data = (kernel_ulong_t)&(cfg), \
}

#define MTK_BAR_0_1_IDX                 0
#define MTK_BAR_2_3_IDX                 2

#define MTK_IRQ_CNT_MAX				32
#define MTK_IRQ_NAME_LEN			32

#define ATR_PORT_OFFSET				0x100
#define ATR_TABLE_OFFSET			0x20
#define ATR_TABLE_NUM_PER_ATR			8
#define ATR_PCIE_REG_TRSL_ADDR			0x10000000
#define ATR_PCIE_REG_SIZE			0x00400000
#define ATR_PCIE_REG_PORT			ATR_SRC_PCI_WIN0
#define ATR_PCIE_REG_TABLE_NUM			1
#define ATR_PCIE_REG_TRSL_PORT			ATR_DST_AXIM_0
#define ATR_PCIE_DEV_DMA_SRC_ADDR		0x00000000
#define ATR_PCIE_DEV_DMA_TRANSPARENT		1
#define ATR_PCIE_DEV_DMA_SIZE			0
#define ATR_PCIE_DEV_DMA_TABLE_NUM		0
#define ATR_PCIE_DEV_DMA_TRSL_ADDR		0x00000000

struct mtk_pci_irq_desc {
	struct mtk_md_dev *mdev;
	u32 msix_bits;
	char name[MTK_IRQ_NAME_LEN];
};

struct mtk_pci_dev_cfg {
	u32 mhccif_rc_base_addr;
	int irq_tbl[MTK_IRQ_SRC_MAX];
	int (*atr_init)(struct mtk_md_dev *mdev);
};

extern const struct mtk_pci_dev_cfg mtk_dev_cfg_0900;

struct mtk_pci_priv {
	struct mtk_md_dev *mdev;
	const struct mtk_pci_dev_cfg *cfg;
	void __iomem *bar23_addr;
	void __iomem *mac_reg_base;
	void __iomem *ext_reg_base;
	int irq_cnt;
	int irq_type;
	/* irq_cb_lock: protects irq_cb_list[] and irq_cb_data[] */
	spinlock_t irq_cb_lock;
	void *irq_cb_data[MTK_IRQ_CNT_MAX];

	int (*irq_cb_list[MTK_IRQ_CNT_MAX])(int irq_id, void *data);
	struct mtk_pci_irq_desc irq_desc[MTK_IRQ_CNT_MAX];
	struct list_head mhccif_cb_list;
	/* mhccif_lock: lock to protect mhccif_cb_list */
	spinlock_t mhccif_lock;
	struct work_struct mhccif_work;
	int mhccif_irq_id;
	struct pci_saved_state *saved_state;
};

struct mtk_atr_cfg {
	u64 src_addr;
	u64 trsl_addr;
	u64 size;
	u32 port;      /* Port number */
	u32 table;     /* Table number (8 tables for each port) */
	u32 trsl_id;
	u32 trsl_param;
	u32 transparent;
};

/* BAR 0/1 MMIO access */
static inline u32 mtk_pci_mac_read32(struct mtk_pci_priv *priv, u64 addr)
{
	return ioread32(priv->mac_reg_base + addr);
}

static inline void mtk_pci_mac_write32(struct mtk_pci_priv *priv, u64 addr, u32 val)
{
	iowrite32(val, priv->mac_reg_base + addr);
}

/* BAR 2/3 MMIO access */
static inline u32 mtk_pci_read32(struct mtk_md_dev *mdev, u64 addr)
{
	return ioread32(((struct mtk_pci_priv *)mdev->hw_priv)->ext_reg_base + addr);
}

static inline void mtk_pci_write32(struct mtk_md_dev *mdev, u64 addr, u32 val)
{
	iowrite32(val, ((struct mtk_pci_priv *)mdev->hw_priv)->ext_reg_base + addr);
}

/* Device operations */
u32 mtk_pci_get_dev_state(struct mtk_md_dev *mdev);
void mtk_pci_ack_dev_state(struct mtk_md_dev *mdev, u32 state);
u32 mtk_pci_get_dev_cfg(struct mtk_md_dev *mdev);
/* IRQ Related operations */
int mtk_pci_get_irq_id(struct mtk_md_dev *mdev, enum mtk_irq_src irq_src);
int mtk_pci_get_virq_id(struct mtk_md_dev *mdev, int irq_id);
int mtk_pci_register_irq(struct mtk_md_dev *mdev, int irq_id,
			 int (*irq_cb)(int irq_id, void *data), void *data);
int mtk_pci_unregister_irq(struct mtk_md_dev *mdev, int irq_id);
int mtk_pci_mask_irq(struct mtk_md_dev *mdev, int irq_id);
int mtk_pci_unmask_irq(struct mtk_md_dev *mdev, int irq_id);
int mtk_pci_clear_irq(struct mtk_md_dev *mdev, int irq_id);
/* External event related */
int mtk_pci_register_ext_evt(struct mtk_md_dev *mdev, u32 chs,
			     int (*evt_cb)(u32 status, void *data), void *data);
void mtk_pci_unregister_ext_evt(struct mtk_md_dev *mdev, u32 chs);
void mtk_pci_mask_ext_evt(struct mtk_md_dev *mdev, u32 chs);
void mtk_pci_unmask_ext_evt(struct mtk_md_dev *mdev, u32 chs);
void mtk_pci_clear_ext_evt(struct mtk_md_dev *mdev, u32 chs);
int mtk_pci_send_ext_evt(struct mtk_md_dev *mdev, u32 ch);
int mtk_pci_pldr(struct mtk_md_dev *mdev);
bool mtk_pci_link_check(struct mtk_md_dev *mdev);
int mtk_pci_setup_atr(struct mtk_md_dev *mdev, struct mtk_atr_cfg *cfg);
void mtk_pci_atr_disable(struct mtk_pci_priv *priv);

#endif /* __MTK_PCI_H__ */
