# SPDX-License-Identifier: GPL-2.0-only

ccflags-y += -I$(src)
ccflags-y += -I$(src)/..

obj-$(CONFIG_MTK_T9XX_PCI) += mtk_t9xx_pcie.o

mtk_t9xx_pcie-y := \
	mtk_pci_drv_m9xx.o \
	mtk_cldma_drv_m9xx.o \
	mtk_ctrl_cfg_m9xx.o \
	mtk_pci.o \
	mtk_trans_ctrl.o \
	mtk_cldma.o \
	mtk_cldma_drv.o
