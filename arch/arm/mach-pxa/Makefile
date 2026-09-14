# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the linux kernel.
#

# Common support (must be linked before board specific support)
obj-y				+= devices.o generic.o irq.o reset.o
obj-$(CONFIG_PM)		+= pm.o sleep.o standby.o

# Generic drivers that other drivers may depend upon

# SoC-specific code
obj-$(CONFIG_PXA25x)		+= mfp-pxa2xx.o pxa2xx.o pxa25x.o
obj-$(CONFIG_PXA27x)		+= mfp-pxa2xx.o pxa2xx.o pxa27x.o
obj-$(CONFIG_PXA3xx)		+= mfp-pxa3xx.o pxa3xx.o smemc.o
obj-$(CONFIG_CPU_PXA300)	+= pxa300.o
obj-$(CONFIG_CPU_PXA320)	+= pxa320.o

# NOTE: keep the order of boards in accordance to their order in Kconfig

# Device Tree support
obj-$(CONFIG_MACH_PXA25X_DT)	+= pxa-dt.o
obj-$(CONFIG_MACH_PXA27X_DT)	+= pxa-dt.o
obj-$(CONFIG_MACH_PXA3XX_DT)	+= pxa-dt.o
