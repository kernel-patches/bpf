# SPDX-License-Identifier: GPL-2.0-only

ccflags-y += -I$(src)/pcie
ccflags-y += -I$(src)

obj-$(CONFIG_MTK_T9XX) += mtk_t9xx.o
obj-$(CONFIG_MTK_T9XX_PCI) += pcie/

mtk_t9xx-y := \
	mtk_dev.o \
	mtk_ctrl_plane.o \
	mtk_port.o \
	mtk_port_io.o
