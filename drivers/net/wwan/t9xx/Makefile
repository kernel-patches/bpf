# SPDX-License-Identifier: GPL-2.0-only

ccflags-y += -I$(src)/pcie
ccflags-y += -I$(src)

obj-$(CONFIG_MTK_T9XX) += mtk_t9xx.o

mtk_t9xx-y := \
	mtk_ctrl_plane.o \
	pcie/mtk_pci.o \
	pcie/mtk_trans_ctrl.o \
	pcie/mtk_cldma.o \
	pcie/mtk_cldma_drv.o
