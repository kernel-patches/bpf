# SPDX-License-Identifier: GPL-2.0-only

ccflags-y += -I$(src)/pcie
ccflags-y += -I$(src)

obj-$(CONFIG_MTK_T9XX) += mtk_t9xx.o

mtk_t9xx-y := \
	pcie/mtk_pci.o \
	pcie/mtk_pci_drv_m9xx.o
