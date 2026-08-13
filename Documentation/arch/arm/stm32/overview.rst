========================
STM32 ARM Linux Overview
========================

Introduction
------------

The STMicroelectronics STM32 family of Cortex-A microprocessors (MPUs) is
supported by the 'STM32' platform of ARM Linux, support for the Cortex-M
based MCUs has been removed.

Configuration
-------------

For MPUs, use multi_v7 configuration:
        make multi_v7_defconfig

Layout
------

All the files for multiple machine families are located in the platform code
contained in arch/arm/mach-stm32

There is a generic board board-dt.c in the mach folder which support
Flattened Device Tree, which means, it works with any compatible board with
Device Trees.

:Authors:

- Maxime Coquelin <mcoquelin.stm32@gmail.com>
- Ludovic Barre <ludovic.barre@st.com>
- Gerald Baeza <gerald.baeza@st.com>
