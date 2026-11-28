# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2021-2026, Shanghai Yunsilicon Technology Co., Ltd.
# All rights reserved.

ccflags-y += -I$(srctree)/drivers/net/ethernet/yunsilicon/xsc

obj-$(CONFIG_YUNSILICON_XSC_ETH) += xsc_eth.o

xsc_eth-y := main.o xsc_eth_wq.o xsc_eth_txrx.o xsc_eth_tx.o xsc_eth_rx.o
