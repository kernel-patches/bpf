# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the linux kernel.
#

# Common support
obj-y := id.o io.o control.o devices.o fb.o pm.o \
	 common.o dma.o omap-headsmp.o

# OMAP3 hwmod specific
obj-$(CONFIG_ARCH_OMAP3)		+= sram.o omap_hwmod.o \
					  omap_hwmod_common_data.o \
					  omap_hwmod_common_ipblock_data.o \
					  omap_device.o display.o hdq1w.o \
					  i2c.o wd_timer.o

# secure world
obj-y					+= omap-smc.o omap-secure.o

ifneq ($(CONFIG_SND_SOC_OMAP_MCBSP),)
obj-$(CONFIG_OMAP_HWMOD) += mcbsp.o
endif

obj-$(CONFIG_TWL4030_CORE) += omap_twl.o

ifneq ($(CONFIG_MFD_CPCAP),)
obj-y 					+= pmic-cpcap.o
endif

obj-$(CONFIG_SOC_HAS_OMAP2_SDRC)	+= sdrc.o

# SMP support ONLY available for OMAP4

smp-$(CONFIG_SMP)			+= omap-smp.o
smp-$(CONFIG_HOTPLUG_CPU)		+= omap-hotplug.o
omap-4-5-common				=  omap4-common.o omap-wakeupgen.o
obj-$(CONFIG_ARCH_OMAP4)		+= $(omap-4-5-common) $(smp-y) sleep44xx.o
obj-$(CONFIG_SOC_OMAP5)			+= $(omap-4-5-common) $(smp-y) sleep44xx.o
obj-$(CONFIG_SOC_AM43XX)		+= $(omap-4-5-common)
obj-$(CONFIG_SOC_DRA7XX)		+= $(omap-4-5-common) $(smp-y) sleep44xx.o

omap5-dra7-common-$(CONFIG_SOC_HAS_REALTIME_COUNTER) =  timer.o
obj-$(CONFIG_SOC_OMAP5)			+= $(omap5-dra7-common-y)
obj-$(CONFIG_SOC_DRA7XX)		+= $(omap5-dra7-common-y)

# Restart code (OMAP4/5 currently in omap4-common.c)
obj-$(CONFIG_SOC_TI81XX)		+= ti81xx-restart.o
obj-$(CONFIG_SOC_AM33XX)		+= am33xx-restart.o
obj-$(CONFIG_SOC_AM43XX)		+= omap4-restart.o
obj-$(CONFIG_ARCH_OMAP3)		+= omap3-restart.o
obj-$(CONFIG_ARCH_OMAP4)		+= omap4-restart.o
obj-$(CONFIG_SOC_OMAP5)			+= omap4-restart.o
obj-$(CONFIG_SOC_DRA7XX)		+= omap4-restart.o

# SMS/SDRC
# obj-$(CONFIG_ARCH_OMAP3)		+= sdrc3xxx.o

# OPP table initialization
ifeq ($(CONFIG_PM_OPP),y)
obj-$(CONFIG_ARCH_OMAP3)		+= opp3xxx_data.o
obj-$(CONFIG_ARCH_OMAP4)		+= opp4xxx_data.o
endif

# Power Management
omap-4-5-pm-common			= omap-mpuss-lowpower.o
obj-$(CONFIG_ARCH_OMAP4)		+= $(omap-4-5-pm-common)
obj-$(CONFIG_SOC_OMAP5)			+= $(omap-4-5-pm-common)

ifeq ($(CONFIG_PM),y)
obj-$(CONFIG_ARCH_OMAP3)		+= pm34xx.o sleep34xx.o
omap-4-5-pm-common			+= pm44xx.o
obj-$(CONFIG_ARCH_OMAP4)		+= $(omap-4-5-pm-common)
obj-$(CONFIG_SOC_OMAP5)			+= $(omap-4-5-pm-common)
obj-$(CONFIG_SOC_DRA7XX)		+= $(omap-4-5-pm-common)
obj-$(CONFIG_SOC_AM33XX)		+= pm33xx-core.o sleep33xx.o
obj-$(CONFIG_SOC_AM43XX)		+= pm33xx-core.o sleep43xx.o
obj-$(CONFIG_PM_DEBUG)			+= pm-debug.o

obj-$(CONFIG_POWER_AVS_OMAP)		+= sr_device.o
obj-$(CONFIG_POWER_AVS_OMAP_CLASS3)    += smartreflex-class3.o

endif

ifeq ($(CONFIG_CPU_IDLE),y)
obj-$(CONFIG_ARCH_OMAP3)                += cpuidle34xx.o
omap-4-5-idle-common			=  cpuidle44xx.o
obj-$(CONFIG_ARCH_OMAP4)		+= $(omap-4-5-idle-common)
obj-$(CONFIG_SOC_OMAP5)			+= $(omap-4-5-idle-common)
obj-$(CONFIG_SOC_DRA7XX)		+= $(omap-4-5-idle-common)
endif

# PRCM
obj-y					+= prm_common.o cm_common.o
obj-$(CONFIG_ARCH_OMAP3)		+= prm2xxx_3xxx.o prm3xxx.o cm3xxx.o
obj-$(CONFIG_ARCH_OMAP3)		+= vc3xxx_data.o vp3xxx_data.o
omap-prcm-4-5-common			=  cminst44xx.o prm44xx.o \
					   prcm_mpu44xx.o prminst44xx.o \
					   vc44xx_data.o vp44xx_data.o
obj-$(CONFIG_ARCH_OMAP4)		+= $(omap-prcm-4-5-common)
obj-$(CONFIG_SOC_OMAP5)			+= $(omap-prcm-4-5-common)
obj-$(CONFIG_SOC_DRA7XX)		+= $(omap-prcm-4-5-common)
am33xx-43xx-prcm-common			+= prm33xx.o cm33xx.o
obj-$(CONFIG_SOC_TI81XX)		+= $(am33xx-43xx-prcm-common)
obj-$(CONFIG_SOC_AM33XX)		+= $(am33xx-43xx-prcm-common)
obj-$(CONFIG_SOC_AM43XX)		+= $(omap-prcm-4-5-common) \
					   $(am33xx-43xx-prcm-common)

# OMAP voltage domains
voltagedomain-common			:= voltage.o vc.o vp.o
obj-$(CONFIG_ARCH_OMAP3)		+= $(voltagedomain-common)
obj-$(CONFIG_ARCH_OMAP3)		+= voltagedomains3xxx_data.o
obj-$(CONFIG_ARCH_OMAP4)		+= $(voltagedomain-common)
obj-$(CONFIG_ARCH_OMAP4)		+= voltagedomains44xx_data.o
obj-$(CONFIG_SOC_AM33XX)		+= $(voltagedomain-common)
obj-$(CONFIG_SOC_AM43XX)		+= $(voltagedomain-common)
obj-$(CONFIG_SOC_OMAP5)			+= $(voltagedomain-common)
obj-$(CONFIG_SOC_OMAP5)                += voltagedomains54xx_data.o
obj-$(CONFIG_SOC_DRA7XX)		+= $(voltagedomain-common)

# OMAP powerdomain framework
powerdomain-common			+= powerdomain.o powerdomain-common.o
obj-$(CONFIG_ARCH_OMAP3)		+= $(powerdomain-common)
obj-$(CONFIG_ARCH_OMAP3)		+= powerdomains3xxx_data.o
obj-$(CONFIG_ARCH_OMAP3)		+= powerdomains2xxx_3xxx_data.o
obj-$(CONFIG_ARCH_OMAP4)		+= $(powerdomain-common)
obj-$(CONFIG_ARCH_OMAP4)		+= powerdomains44xx_data.o
obj-$(CONFIG_SOC_AM33XX)		+= $(powerdomain-common)
obj-$(CONFIG_SOC_AM33XX)		+= powerdomains33xx_data.o
obj-$(CONFIG_SOC_AM43XX)		+= $(powerdomain-common)
obj-$(CONFIG_SOC_AM43XX)		+= powerdomains43xx_data.o
obj-$(CONFIG_SOC_OMAP5)			+= $(powerdomain-common)
obj-$(CONFIG_SOC_OMAP5)			+= powerdomains54xx_data.o
obj-$(CONFIG_SOC_DRA7XX)		+= $(powerdomain-common)
obj-$(CONFIG_SOC_DRA7XX)		+= powerdomains7xx_data.o

# PRCM clockdomain control
clockdomain-common			+= clockdomain.o
obj-$(CONFIG_ARCH_OMAP3)		+= $(clockdomain-common)
obj-$(CONFIG_ARCH_OMAP3)		+= clockdomains2xxx_3xxx_data.o
obj-$(CONFIG_ARCH_OMAP3)		+= clockdomains3xxx_data.o
obj-$(CONFIG_ARCH_OMAP4)		+= $(clockdomain-common)
obj-$(CONFIG_ARCH_OMAP4)		+= clockdomains44xx_data.o
obj-$(CONFIG_SOC_AM33XX)		+= $(clockdomain-common)
obj-$(CONFIG_SOC_AM33XX)		+= clockdomains33xx_data.o
obj-$(CONFIG_SOC_TI81XX)		+= $(clockdomain-common)
obj-$(CONFIG_SOC_TI81XX)		+= clockdomains81xx_data.o
obj-$(CONFIG_SOC_AM43XX)		+= $(clockdomain-common)
obj-$(CONFIG_SOC_AM43XX)		+= clockdomains43xx_data.o
obj-$(CONFIG_SOC_OMAP5)			+= $(clockdomain-common)
obj-$(CONFIG_SOC_OMAP5)			+= clockdomains54xx_data.o
obj-$(CONFIG_SOC_DRA7XX)		+= $(clockdomain-common)
obj-$(CONFIG_SOC_DRA7XX)		+= clockdomains7xx_data.o

# Clock framework
obj-y					+= clock.o

# hwmod data
obj-$(CONFIG_ARCH_OMAP3)		+= omap_hwmod_2xxx_3xxx_ipblock_data.o
obj-$(CONFIG_ARCH_OMAP3)		+= omap_hwmod_3xxx_data.o
obj-$(CONFIG_SOC_TI81XX)		+= omap_hwmod_81xx_data.o

# Specific board support
obj-$(CONFIG_MACH_OMAP_GENERIC)		+= board-generic.o pdata-quirks.o

# Platform specific device init code

obj-y					+= omap_phy_internal.o

$(obj)/pm-asm-offsets.h: $(obj)/pm-asm-offsets.s FORCE
	$(call filechk,offsets,__TI_PM_ASM_OFFSETS_H__)

$(obj)/sleep33xx.o $(obj)/sleep43xx.o: $(obj)/pm-asm-offsets.h

targets += pm-asm-offsets.s
clean-files += pm-asm-offsets.h

obj-$(CONFIG_OMAP_IOMMU)		+= omap-iommu.o
