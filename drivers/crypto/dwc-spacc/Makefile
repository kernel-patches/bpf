# SPDX-License-Identifier: GPL-2.0-only
obj-$(CONFIG_CRYPTO_DEV_SPACC) += snps-spacc.o

snps-spacc-y := spacc_hal.o spacc_core.o \
spacc_manager.o spacc_interrupt.o spacc_device.o

snps-spacc-$(CONFIG_CRYPTO_DEV_SPACC_HASH) += spacc_ahash.o
