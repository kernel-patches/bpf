/*
 * \file radeon_drv.c
 * ATI Radeon driver
 *
 * \author Gareth Hughes <gareth@valinux.com>
 */

/*
 * Copyright 2000 VA Linux Systems, Inc., Sunnyvale, California.
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * VA LINUX SYSTEMS AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <linux/aperture.h>
#include <linux/compat.h>
#include <linux/module.h>
#include <linux/pm_runtime.h>
#include <linux/vga_switcheroo.h>
#include <linux/mmu_notifier.h>
#include <linux/pci.h>

#include <drm/clients/drm_client_setup.h>
#include <drm/drm_drv.h>
#include <drm/drm_file.h>
#include <drm/drm_fourcc.h>
#include <drm/drm_gem.h>
#include <drm/drm_ioctl.h>
#include <drm/drm_probe_helper.h>
#include <drm/drm_vblank.h>
#include <drm/radeon_drm.h>

#include "radeon_drv.h"
#include "radeon.h"
#include "radeon_kms.h"
#include "radeon_ttm.h"
#include "radeon_device.h"
#include "radeon_prime.h"

/*
 * KMS wrapper.
 * - 2.0.0 - initial interface
 * - 2.1.0 - add square tiling interface
 * - 2.2.0 - add r6xx/r7xx const buffer support
 * - 2.3.0 - add MSPOS + 3D texture + r500 VAP regs
 * - 2.4.0 - add crtc id query
 * - 2.5.0 - add get accel 2 to work around ddx breakage for evergreen
 * - 2.6.0 - add tiling config query (r6xx+), add initial HiZ support (r300->r500)
 *   2.7.0 - fixups for r600 2D tiling support. (no external ABI change), add eg dyn gpr regs
 *   2.8.0 - pageflip support, r500 US_FORMAT regs. r500 ARGB2101010 colorbuf, r300->r500 CMASK, clock crystal query
 *   2.9.0 - r600 tiling (s3tc,rgtc) working, SET_PREDICATION packet 3 on r600 + eg, backend query
 *   2.10.0 - fusion 2D tiling
 *   2.11.0 - backend map, initial compute support for the CS checker
 *   2.12.0 - RADEON_CS_KEEP_TILING_FLAGS
 *   2.13.0 - virtual memory support, streamout
 *   2.14.0 - add evergreen tiling informations
 *   2.15.0 - add max_pipes query
 *   2.16.0 - fix evergreen 2D tiled surface calculation
 *   2.17.0 - add STRMOUT_BASE_UPDATE for r7xx
 *   2.18.0 - r600-eg: allow "invalid" DB formats
 *   2.19.0 - r600-eg: MSAA textures
 *   2.20.0 - r600-si: RADEON_INFO_TIMESTAMP query
 *   2.21.0 - r600-r700: FMASK and CMASK
 *   2.22.0 - r600 only: RESOLVE_BOX allowed
 *   2.23.0 - allow STRMOUT_BASE_UPDATE on RS780 and RS880
 *   2.24.0 - eg only: allow MIP_ADDRESS=0 for MSAA textures
 *   2.25.0 - eg+: new info request for num SE and num SH
 *   2.26.0 - r600-eg: fix htile size computation
 *   2.27.0 - r600-SI: Add CS ioctl support for async DMA
 *   2.28.0 - r600-eg: Add MEM_WRITE packet support
 *   2.29.0 - R500 FP16 color clear registers
 *   2.30.0 - fix for FMASK texturing
 *   2.31.0 - Add fastfb support for rs690
 *   2.32.0 - new info request for rings working
 *   2.33.0 - Add SI tiling mode array query
 *   2.34.0 - Add CIK tiling mode array query
 *   2.35.0 - Add CIK macrotile mode array query
 *   2.36.0 - Fix CIK DCE tiling setup
 *   2.37.0 - allow GS ring setup on r6xx/r7xx
 *   2.38.0 - RADEON_GEM_OP (GET_INITIAL_DOMAIN, SET_INITIAL_DOMAIN),
 *            CIK: 1D and linear tiling modes contain valid PIPE_CONFIG
 *   2.39.0 - Add INFO query for number of active CUs
 *   2.40.0 - Add RADEON_GEM_GTT_WC/UC, flush HDP cache before submitting
 *            CS to GPU on >= r600
 *   2.41.0 - evergreen/cayman: Add SET_BASE/DRAW_INDIRECT command parsing support
 *   2.42.0 - Add VCE/VUI (Video Usability Information) support
 *   2.43.0 - RADEON_INFO_GPU_RESET_COUNTER
 *   2.44.0 - SET_APPEND_CNT packet3 support
 *   2.45.0 - Allow setting shader registers using DMA/COPY packet3 on SI
 *   2.46.0 - Add PFP_SYNC_ME support on evergreen
 *   2.47.0 - Add UVD_NO_OP register support
 *   2.48.0 - TA_CS_BC_BASE_ADDR allowed on SI
 *   2.49.0 - DRM_RADEON_GEM_INFO ioctl returns correct vram_size/visible values
 *   2.50.0 - Allows unaligned shader loads on CIK. (needed by OpenGL)
 *   2.51.0 - Add evergreen/cayman OpenGL 4.6 compatibility
 */
#define KMS_DRIVER_MAJOR	2
#define KMS_DRIVER_MINOR	51
#define KMS_DRIVER_PATCHLEVEL	0

int radeon_no_wb;
int radeon_modeset = -1;
int radeon_dynclks = -1;
int radeon_r4xx_atom;
int radeon_agpmode = -1;
int radeon_vram_limit;
int radeon_gart_size = -1; /* auto */
int radeon_benchmarking;
int radeon_testing;
int radeon_connector_table;
int radeon_tv = 1;
int radeon_audio = -1;
int radeon_disp_priority;
int radeon_hw_i2c;
int radeon_pcie_gen2 = -1;
int radeon_msi = -1;
int radeon_lockup_timeout = 10000;
int radeon_fastfb;
int radeon_dpm = -1;
int radeon_aspm = -1;
int radeon_runtime_pm = -1;
int radeon_hard_reset;
int radeon_vm_size = 8;
int radeon_vm_block_size = -1;
int radeon_deep_color;
int radeon_use_pflipirq = 2;
int radeon_bapm = -1;
int radeon_backlight = -1;
int radeon_auxch = -1;
int radeon_uvd = 1;
int radeon_vce = 1;

MODULE_PARM_DESC(no_wb, "Disable AGP writeback for scratch registers");
module_param_named(no_wb, radeon_no_wb, int, 0444);

MODULE_PARM_DESC(modeset, "Disable/Enable modesetting");
module_param_named(modeset, radeon_modeset, int, 0400);

MODULE_PARM_DESC(dynclks, "Disable/Enable dynamic clocks");
module_param_named(dynclks, radeon_dynclks, int, 0444);

MODULE_PARM_DESC(r4xx_atom, "Enable ATOMBIOS modesetting for R4xx");
module_param_named(r4xx_atom, radeon_r4xx_atom, int, 0444);

MODULE_PARM_DESC(vramlimit, "Restrict VRAM for testing, in megabytes");
module_param_named(vramlimit, radeon_vram_limit, int, 0600);

MODULE_PARM_DESC(agpmode, "AGP Mode (-1 == PCI)");
module_param_named(agpmode, radeon_agpmode, int, 0444);

MODULE_PARM_DESC(gartsize, "Size of PCIE/IGP gart to setup in megabytes (32, 64, etc., -1 = auto)");
module_param_named(gartsize, radeon_gart_size, int, 0600);

MODULE_PARM_DESC(benchmark, "Run benchmark");
module_param_named(benchmark, radeon_benchmarking, int, 0444);

MODULE_PARM_DESC(test, "Run tests");
module_param_named(test, radeon_testing, int, 0444);

MODULE_PARM_DESC(connector_table, "Force connector table");
module_param_named(connector_table, radeon_connector_table, int, 0444);

MODULE_PARM_DESC(tv, "TV enable (0 = disable)");
module_param_named(tv, radeon_tv, int, 0444);

MODULE_PARM_DESC(audio, "Audio enable (-1 = auto, 0 = disable, 1 = enable)");
module_param_named(audio, radeon_audio, int, 0444);

MODULE_PARM_DESC(disp_priority, "Display Priority (0 = auto, 1 = normal, 2 = high)");
module_param_named(disp_priority, radeon_disp_priority, int, 0444);

MODULE_PARM_DESC(hw_i2c, "hw i2c engine enable (0 = disable)");
module_param_named(hw_i2c, radeon_hw_i2c, int, 0444);

MODULE_PARM_DESC(pcie_gen2, "PCIE Gen2 mode (-1 = auto, 0 = disable, 1 = enable)");
module_param_named(pcie_gen2, radeon_pcie_gen2, int, 0444);

MODULE_PARM_DESC(msi, "MSI support (1 = enable, 0 = disable, -1 = auto)");
module_param_named(msi, radeon_msi, int, 0444);

MODULE_PARM_DESC(lockup_timeout, "GPU lockup timeout in ms (default 10000 = 10 seconds, 0 = disable)");
module_param_named(lockup_timeout, radeon_lockup_timeout, int, 0444);

MODULE_PARM_DESC(fastfb, "Direct FB access for IGP chips (0 = disable, 1 = enable)");
module_param_named(fastfb, radeon_fastfb, int, 0444);

MODULE_PARM_DESC(dpm, "DPM support (1 = enable, 0 = disable, -1 = auto)");
module_param_named(dpm, radeon_dpm, int, 0444);

MODULE_PARM_DESC(aspm, "ASPM support (1 = enable, 0 = disable, -1 = auto)");
module_param_named(aspm, radeon_aspm, int, 0444);

MODULE_PARM_DESC(runpm, "PX runtime pm (1 = force enable, 0 = disable, -1 = PX only default)");
module_param_named(runpm, radeon_runtime_pm, int, 0444);

MODULE_PARM_DESC(hard_reset, "PCI config reset (1 = force enable, 0 = disable (default))");
module_param_named(hard_reset, radeon_hard_reset, int, 0444);

MODULE_PARM_DESC(vm_size, "VM address space size in gigabytes (default 4GB)");
module_param_named(vm_size, radeon_vm_size, int, 0444);

MODULE_PARM_DESC(vm_block_size, "VM page table size in bits (default depending on vm_size)");
module_param_named(vm_block_size, radeon_vm_block_size, int, 0444);

MODULE_PARM_DESC(deep_color, "Deep Color support (1 = enable, 0 = disable (default))");
module_param_named(deep_color, radeon_deep_color, int, 0444);

MODULE_PARM_DESC(use_pflipirq, "Pflip irqs for pageflip completion (0 = disable, 1 = as fallback, 2 = exclusive (default))");
module_param_named(use_pflipirq, radeon_use_pflipirq, int, 0444);

MODULE_PARM_DESC(bapm, "BAPM support (1 = enable, 0 = disable, -1 = auto)");
module_param_named(bapm, radeon_bapm, int, 0444);

MODULE_PARM_DESC(backlight, "backlight support (1 = enable, 0 = disable, -1 = auto)");
module_param_named(backlight, radeon_backlight, int, 0444);

MODULE_PARM_DESC(auxch, "Use native auxch experimental support (1 = enable, 0 = disable, -1 = auto)");
module_param_named(auxch, radeon_auxch, int, 0444);

MODULE_PARM_DESC(uvd, "uvd enable/disable uvd support (1 = enable, 0 = disable)");
module_param_named(uvd, radeon_uvd, int, 0444);

MODULE_PARM_DESC(vce, "vce enable/disable vce support (1 = enable, 0 = disable)");
module_param_named(vce, radeon_vce, int, 0444);

int radeon_si_support = -1;
MODULE_PARM_DESC(si_support, "SI support (1 = enabled, 0 = disabled, -1 = default)");
module_param_named(si_support, radeon_si_support, int, 0444);

int radeon_cik_support = -1;
MODULE_PARM_DESC(cik_support, "CIK support (1 = enabled, 0 = disabled, -1 = default)");
module_param_named(cik_support, radeon_cik_support, int, 0444);

static const struct pci_device_id pciidlist[] = {
	{ PCI_DEVICE(0x1002, 0x1304), .driver_data = CHIP_KAVERI|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x1305), .driver_data = CHIP_KAVERI|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x1306), .driver_data = CHIP_KAVERI|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x1307), .driver_data = CHIP_KAVERI|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x1309), .driver_data = CHIP_KAVERI|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x130A), .driver_data = CHIP_KAVERI|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x130B), .driver_data = CHIP_KAVERI|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x130C), .driver_data = CHIP_KAVERI|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x130D), .driver_data = CHIP_KAVERI|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x130E), .driver_data = CHIP_KAVERI|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x130F), .driver_data = CHIP_KAVERI|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x1310), .driver_data = CHIP_KAVERI|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x1311), .driver_data = CHIP_KAVERI|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x1312), .driver_data = CHIP_KAVERI|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x1313), .driver_data = CHIP_KAVERI|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x1315), .driver_data = CHIP_KAVERI|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x1316), .driver_data = CHIP_KAVERI|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x1317), .driver_data = CHIP_KAVERI|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x1318), .driver_data = CHIP_KAVERI|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x131B), .driver_data = CHIP_KAVERI|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x131C), .driver_data = CHIP_KAVERI|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x131D), .driver_data = CHIP_KAVERI|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x3150), .driver_data = CHIP_RV380|RADEON_IS_MOBILITY },
	{ PCI_DEVICE(0x1002, 0x3151), .driver_data = CHIP_RV380|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x3152), .driver_data = CHIP_RV380|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x3154), .driver_data = CHIP_RV380|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x3155), .driver_data = CHIP_RV380|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x3E50), .driver_data = CHIP_RV380|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x3E54), .driver_data = CHIP_RV380|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x4136), .driver_data = CHIP_RS100|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x4137), .driver_data = CHIP_RS200|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x4144), .driver_data = CHIP_R300 },
	{ PCI_DEVICE(0x1002, 0x4145), .driver_data = CHIP_R300 },
	{ PCI_DEVICE(0x1002, 0x4146), .driver_data = CHIP_R300 },
	{ PCI_DEVICE(0x1002, 0x4147), .driver_data = CHIP_R300 },
	{ PCI_DEVICE(0x1002, 0x4148), .driver_data = CHIP_R350 },
	{ PCI_DEVICE(0x1002, 0x4149), .driver_data = CHIP_R350 },
	{ PCI_DEVICE(0x1002, 0x414A), .driver_data = CHIP_R350 },
	{ PCI_DEVICE(0x1002, 0x414B), .driver_data = CHIP_R350 },
	{ PCI_DEVICE(0x1002, 0x4150), .driver_data = CHIP_RV350 },
	{ PCI_DEVICE(0x1002, 0x4151), .driver_data = CHIP_RV350 },
	{ PCI_DEVICE(0x1002, 0x4152), .driver_data = CHIP_RV350 },
	{ PCI_DEVICE(0x1002, 0x4153), .driver_data = CHIP_RV350 },
	{ PCI_DEVICE(0x1002, 0x4154), .driver_data = CHIP_RV350 },
	{ PCI_DEVICE(0x1002, 0x4155), .driver_data = CHIP_RV350 },
	{ PCI_DEVICE(0x1002, 0x4156), .driver_data = CHIP_RV350 },
	{ PCI_DEVICE(0x1002, 0x4237), .driver_data = CHIP_RS200|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x4242), .driver_data = CHIP_R200 },
	{ PCI_DEVICE(0x1002, 0x4336), .driver_data = CHIP_RS100|RADEON_IS_IGP|RADEON_IS_MOBILITY },
	{ PCI_DEVICE(0x1002, 0x4337), .driver_data = CHIP_RS200|RADEON_IS_IGP|RADEON_IS_MOBILITY },
	{ PCI_DEVICE(0x1002, 0x4437), .driver_data = CHIP_RS200|RADEON_IS_IGP|RADEON_IS_MOBILITY },
	{ PCI_DEVICE(0x1002, 0x4966), .driver_data = CHIP_RV250 },
	{ PCI_DEVICE(0x1002, 0x4967), .driver_data = CHIP_RV250 },
	{ PCI_DEVICE(0x1002, 0x4A48), .driver_data = CHIP_R420|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x4A49), .driver_data = CHIP_R420|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x4A4A), .driver_data = CHIP_R420|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x4A4B), .driver_data = CHIP_R420|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x4A4C), .driver_data = CHIP_R420|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x4A4D), .driver_data = CHIP_R420|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x4A4E), .driver_data = CHIP_R420|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x4A4F), .driver_data = CHIP_R420|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x4A50), .driver_data = CHIP_R420|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x4A54), .driver_data = CHIP_R420|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x4B48), .driver_data = CHIP_R420|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x4B49), .driver_data = CHIP_R420|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x4B4A), .driver_data = CHIP_R420|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x4B4B), .driver_data = CHIP_R420|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x4B4C), .driver_data = CHIP_R420|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x4C57), .driver_data = CHIP_RV200|RADEON_IS_MOBILITY },
	{ PCI_DEVICE(0x1002, 0x4C58), .driver_data = CHIP_RV200|RADEON_IS_MOBILITY },
	{ PCI_DEVICE(0x1002, 0x4C59), .driver_data = CHIP_RV100|RADEON_IS_MOBILITY },
	{ PCI_DEVICE(0x1002, 0x4C5A), .driver_data = CHIP_RV100|RADEON_IS_MOBILITY },
	{ PCI_DEVICE(0x1002, 0x4C64), .driver_data = CHIP_RV250|RADEON_IS_MOBILITY },
	{ PCI_DEVICE(0x1002, 0x4C66), .driver_data = CHIP_RV250|RADEON_IS_MOBILITY },
	{ PCI_DEVICE(0x1002, 0x4C67), .driver_data = CHIP_RV250|RADEON_IS_MOBILITY },
	{ PCI_DEVICE(0x1002, 0x4E44), .driver_data = CHIP_R300 },
	{ PCI_DEVICE(0x1002, 0x4E45), .driver_data = CHIP_R300 },
	{ PCI_DEVICE(0x1002, 0x4E46), .driver_data = CHIP_R300 },
	{ PCI_DEVICE(0x1002, 0x4E47), .driver_data = CHIP_R300 },
	{ PCI_DEVICE(0x1002, 0x4E48), .driver_data = CHIP_R350 },
	{ PCI_DEVICE(0x1002, 0x4E49), .driver_data = CHIP_R350 },
	{ PCI_DEVICE(0x1002, 0x4E4A), .driver_data = CHIP_R350 },
	{ PCI_DEVICE(0x1002, 0x4E4B), .driver_data = CHIP_R350 },
	{ PCI_DEVICE(0x1002, 0x4E50), .driver_data = CHIP_RV350|RADEON_IS_MOBILITY },
	{ PCI_DEVICE(0x1002, 0x4E51), .driver_data = CHIP_RV350|RADEON_IS_MOBILITY },
	{ PCI_DEVICE(0x1002, 0x4E52), .driver_data = CHIP_RV350|RADEON_IS_MOBILITY },
	{ PCI_DEVICE(0x1002, 0x4E53), .driver_data = CHIP_RV350|RADEON_IS_MOBILITY },
	{ PCI_DEVICE(0x1002, 0x4E54), .driver_data = CHIP_RV350|RADEON_IS_MOBILITY },
	{ PCI_DEVICE(0x1002, 0x4E56), .driver_data = CHIP_RV350|RADEON_IS_MOBILITY },
	{ PCI_DEVICE(0x1002, 0x5144), .driver_data = CHIP_R100|RADEON_SINGLE_CRTC },
	{ PCI_DEVICE(0x1002, 0x5145), .driver_data = CHIP_R100|RADEON_SINGLE_CRTC },
	{ PCI_DEVICE(0x1002, 0x5146), .driver_data = CHIP_R100|RADEON_SINGLE_CRTC },
	{ PCI_DEVICE(0x1002, 0x5147), .driver_data = CHIP_R100|RADEON_SINGLE_CRTC },
	{ PCI_DEVICE(0x1002, 0x5148), .driver_data = CHIP_R200 },
	{ PCI_DEVICE(0x1002, 0x514C), .driver_data = CHIP_R200 },
	{ PCI_DEVICE(0x1002, 0x514D), .driver_data = CHIP_R200 },
	{ PCI_DEVICE(0x1002, 0x5157), .driver_data = CHIP_RV200 },
	{ PCI_DEVICE(0x1002, 0x5158), .driver_data = CHIP_RV200 },
	{ PCI_DEVICE(0x1002, 0x5159), .driver_data = CHIP_RV100 },
	{ PCI_DEVICE(0x1002, 0x515A), .driver_data = CHIP_RV100 },
	{ PCI_DEVICE(0x1002, 0x515E), .driver_data = CHIP_RV100|RADEON_SINGLE_CRTC },
	{ PCI_DEVICE(0x1002, 0x5460), .driver_data = CHIP_RV380|RADEON_IS_MOBILITY },
	{ PCI_DEVICE(0x1002, 0x5462), .driver_data = CHIP_RV380|RADEON_IS_MOBILITY },
	{ PCI_DEVICE(0x1002, 0x5464), .driver_data = CHIP_RV380|RADEON_IS_MOBILITY },
	{ PCI_DEVICE(0x1002, 0x5548), .driver_data = CHIP_R423|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x5549), .driver_data = CHIP_R423|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x554A), .driver_data = CHIP_R423|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x554B), .driver_data = CHIP_R423|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x554C), .driver_data = CHIP_R423|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x554D), .driver_data = CHIP_R423|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x554E), .driver_data = CHIP_R423|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x554F), .driver_data = CHIP_R423|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x5550), .driver_data = CHIP_R423|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x5551), .driver_data = CHIP_R423|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x5552), .driver_data = CHIP_R423|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x5554), .driver_data = CHIP_R423|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x564A), .driver_data = CHIP_RV410|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x564B), .driver_data = CHIP_RV410|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x564F), .driver_data = CHIP_RV410|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x5652), .driver_data = CHIP_RV410|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x5653), .driver_data = CHIP_RV410|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x5657), .driver_data = CHIP_RV410|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x5834), .driver_data = CHIP_RS300|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x5835), .driver_data = CHIP_RS300|RADEON_IS_IGP|RADEON_IS_MOBILITY },
	{ PCI_DEVICE(0x1002, 0x5954), .driver_data = CHIP_RS480|RADEON_IS_IGP|RADEON_IS_MOBILITY|RADEON_IS_IGPGART },
	{ PCI_DEVICE(0x1002, 0x5955), .driver_data = CHIP_RS480|RADEON_IS_IGP|RADEON_IS_MOBILITY|RADEON_IS_IGPGART },
	{ PCI_DEVICE(0x1002, 0x5974), .driver_data = CHIP_RS480|RADEON_IS_IGP|RADEON_IS_MOBILITY|RADEON_IS_IGPGART },
	{ PCI_DEVICE(0x1002, 0x5975), .driver_data = CHIP_RS480|RADEON_IS_IGP|RADEON_IS_MOBILITY|RADEON_IS_IGPGART },
	{ PCI_DEVICE(0x1002, 0x5960), .driver_data = CHIP_RV280 },
	{ PCI_DEVICE(0x1002, 0x5961), .driver_data = CHIP_RV280 },
	{ PCI_DEVICE(0x1002, 0x5962), .driver_data = CHIP_RV280 },
	{ PCI_DEVICE(0x1002, 0x5964), .driver_data = CHIP_RV280 },
	{ PCI_DEVICE(0x1002, 0x5965), .driver_data = CHIP_RV280 },
	{ PCI_DEVICE(0x1002, 0x5969), .driver_data = CHIP_RV100|RADEON_SINGLE_CRTC },
	{ PCI_DEVICE(0x1002, 0x5a41), .driver_data = CHIP_RS400|RADEON_IS_IGP|RADEON_IS_IGPGART },
	{ PCI_DEVICE(0x1002, 0x5a42), .driver_data = CHIP_RS400|RADEON_IS_IGP|RADEON_IS_MOBILITY|RADEON_IS_IGPGART },
	{ PCI_DEVICE(0x1002, 0x5a61), .driver_data = CHIP_RS400|RADEON_IS_IGP|RADEON_IS_IGPGART },
	{ PCI_DEVICE(0x1002, 0x5a62), .driver_data = CHIP_RS400|RADEON_IS_IGP|RADEON_IS_MOBILITY|RADEON_IS_IGPGART },
	{ PCI_DEVICE(0x1002, 0x5b60), .driver_data = CHIP_RV380|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x5b62), .driver_data = CHIP_RV380|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x5b63), .driver_data = CHIP_RV380|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x5b64), .driver_data = CHIP_RV380|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x5b65), .driver_data = CHIP_RV380|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x5c61), .driver_data = CHIP_RV280|RADEON_IS_MOBILITY },
	{ PCI_DEVICE(0x1002, 0x5c63), .driver_data = CHIP_RV280|RADEON_IS_MOBILITY },
	{ PCI_DEVICE(0x1002, 0x5d48), .driver_data = CHIP_R423|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x5d49), .driver_data = CHIP_R423|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x5d4a), .driver_data = CHIP_R423|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x5d4c), .driver_data = CHIP_R423|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x5d4d), .driver_data = CHIP_R423|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x5d4e), .driver_data = CHIP_R423|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x5d4f), .driver_data = CHIP_R423|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x5d50), .driver_data = CHIP_R423|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x5d52), .driver_data = CHIP_R423|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x5d57), .driver_data = CHIP_R423|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x5e48), .driver_data = CHIP_RV410|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x5e4a), .driver_data = CHIP_RV410|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x5e4b), .driver_data = CHIP_RV410|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x5e4c), .driver_data = CHIP_RV410|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x5e4d), .driver_data = CHIP_RV410|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x5e4f), .driver_data = CHIP_RV410|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6600), .driver_data = CHIP_OLAND|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6601), .driver_data = CHIP_OLAND|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6602), .driver_data = CHIP_OLAND|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6603), .driver_data = CHIP_OLAND|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6604), .driver_data = CHIP_OLAND|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6605), .driver_data = CHIP_OLAND|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6606), .driver_data = CHIP_OLAND|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6607), .driver_data = CHIP_OLAND|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6608), .driver_data = CHIP_OLAND|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6610), .driver_data = CHIP_OLAND|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6611), .driver_data = CHIP_OLAND|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6613), .driver_data = CHIP_OLAND|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6617), .driver_data = CHIP_OLAND|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6620), .driver_data = CHIP_OLAND|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6621), .driver_data = CHIP_OLAND|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6623), .driver_data = CHIP_OLAND|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6631), .driver_data = CHIP_OLAND|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6640), .driver_data = CHIP_BONAIRE|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6641), .driver_data = CHIP_BONAIRE|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6646), .driver_data = CHIP_BONAIRE|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6647), .driver_data = CHIP_BONAIRE|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6649), .driver_data = CHIP_BONAIRE|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6650), .driver_data = CHIP_BONAIRE|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6651), .driver_data = CHIP_BONAIRE|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6658), .driver_data = CHIP_BONAIRE|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x665c), .driver_data = CHIP_BONAIRE|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x665d), .driver_data = CHIP_BONAIRE|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x665f), .driver_data = CHIP_BONAIRE|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6660), .driver_data = CHIP_HAINAN|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6663), .driver_data = CHIP_HAINAN|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6664), .driver_data = CHIP_HAINAN|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6665), .driver_data = CHIP_HAINAN|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6667), .driver_data = CHIP_HAINAN|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x666F), .driver_data = CHIP_HAINAN|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6700), .driver_data = CHIP_CAYMAN|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6701), .driver_data = CHIP_CAYMAN|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6702), .driver_data = CHIP_CAYMAN|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6703), .driver_data = CHIP_CAYMAN|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6704), .driver_data = CHIP_CAYMAN|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6705), .driver_data = CHIP_CAYMAN|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6706), .driver_data = CHIP_CAYMAN|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6707), .driver_data = CHIP_CAYMAN|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6708), .driver_data = CHIP_CAYMAN|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6709), .driver_data = CHIP_CAYMAN|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6718), .driver_data = CHIP_CAYMAN|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6719), .driver_data = CHIP_CAYMAN|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x671c), .driver_data = CHIP_CAYMAN|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x671d), .driver_data = CHIP_CAYMAN|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x671f), .driver_data = CHIP_CAYMAN|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6720), .driver_data = CHIP_BARTS|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6721), .driver_data = CHIP_BARTS|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6722), .driver_data = CHIP_BARTS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6723), .driver_data = CHIP_BARTS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6724), .driver_data = CHIP_BARTS|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6725), .driver_data = CHIP_BARTS|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6726), .driver_data = CHIP_BARTS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6727), .driver_data = CHIP_BARTS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6728), .driver_data = CHIP_BARTS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6729), .driver_data = CHIP_BARTS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6738), .driver_data = CHIP_BARTS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6739), .driver_data = CHIP_BARTS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x673e), .driver_data = CHIP_BARTS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6740), .driver_data = CHIP_TURKS|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6741), .driver_data = CHIP_TURKS|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6742), .driver_data = CHIP_TURKS|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6743), .driver_data = CHIP_TURKS|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6744), .driver_data = CHIP_TURKS|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6745), .driver_data = CHIP_TURKS|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6746), .driver_data = CHIP_TURKS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6747), .driver_data = CHIP_TURKS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6748), .driver_data = CHIP_TURKS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6749), .driver_data = CHIP_TURKS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x674A), .driver_data = CHIP_TURKS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6750), .driver_data = CHIP_TURKS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6751), .driver_data = CHIP_TURKS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6758), .driver_data = CHIP_TURKS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6759), .driver_data = CHIP_TURKS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x675B), .driver_data = CHIP_TURKS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x675D), .driver_data = CHIP_TURKS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x675F), .driver_data = CHIP_TURKS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6760), .driver_data = CHIP_CAICOS|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6761), .driver_data = CHIP_CAICOS|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6762), .driver_data = CHIP_CAICOS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6763), .driver_data = CHIP_CAICOS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6764), .driver_data = CHIP_CAICOS|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6765), .driver_data = CHIP_CAICOS|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6766), .driver_data = CHIP_CAICOS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6767), .driver_data = CHIP_CAICOS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6768), .driver_data = CHIP_CAICOS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6770), .driver_data = CHIP_CAICOS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6771), .driver_data = CHIP_CAICOS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6772), .driver_data = CHIP_CAICOS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6778), .driver_data = CHIP_CAICOS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6779), .driver_data = CHIP_CAICOS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x677B), .driver_data = CHIP_CAICOS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6780), .driver_data = CHIP_TAHITI|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6784), .driver_data = CHIP_TAHITI|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6788), .driver_data = CHIP_TAHITI|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x678A), .driver_data = CHIP_TAHITI|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6790), .driver_data = CHIP_TAHITI|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6791), .driver_data = CHIP_TAHITI|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6792), .driver_data = CHIP_TAHITI|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6798), .driver_data = CHIP_TAHITI|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6799), .driver_data = CHIP_TAHITI|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x679A), .driver_data = CHIP_TAHITI|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x679B), .driver_data = CHIP_TAHITI|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x679E), .driver_data = CHIP_TAHITI|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x679F), .driver_data = CHIP_TAHITI|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x67A0), .driver_data = CHIP_HAWAII|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x67A1), .driver_data = CHIP_HAWAII|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x67A2), .driver_data = CHIP_HAWAII|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x67A8), .driver_data = CHIP_HAWAII|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x67A9), .driver_data = CHIP_HAWAII|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x67AA), .driver_data = CHIP_HAWAII|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x67B0), .driver_data = CHIP_HAWAII|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x67B1), .driver_data = CHIP_HAWAII|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x67B8), .driver_data = CHIP_HAWAII|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x67B9), .driver_data = CHIP_HAWAII|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x67BA), .driver_data = CHIP_HAWAII|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x67BE), .driver_data = CHIP_HAWAII|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6800), .driver_data = CHIP_PITCAIRN|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6801), .driver_data = CHIP_PITCAIRN|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6802), .driver_data = CHIP_PITCAIRN|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6806), .driver_data = CHIP_PITCAIRN|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6808), .driver_data = CHIP_PITCAIRN|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6809), .driver_data = CHIP_PITCAIRN|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6810), .driver_data = CHIP_PITCAIRN|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6811), .driver_data = CHIP_PITCAIRN|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6816), .driver_data = CHIP_PITCAIRN|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6817), .driver_data = CHIP_PITCAIRN|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6818), .driver_data = CHIP_PITCAIRN|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6819), .driver_data = CHIP_PITCAIRN|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6820), .driver_data = CHIP_VERDE|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6821), .driver_data = CHIP_VERDE|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6822), .driver_data = CHIP_VERDE|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6823), .driver_data = CHIP_VERDE|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6824), .driver_data = CHIP_VERDE|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6825), .driver_data = CHIP_VERDE|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6826), .driver_data = CHIP_VERDE|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6827), .driver_data = CHIP_VERDE|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6828), .driver_data = CHIP_VERDE|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6829), .driver_data = CHIP_VERDE|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x682A), .driver_data = CHIP_VERDE|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x682B), .driver_data = CHIP_VERDE|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x682C), .driver_data = CHIP_VERDE|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x682D), .driver_data = CHIP_VERDE|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x682F), .driver_data = CHIP_VERDE|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6830), .driver_data = CHIP_VERDE|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6831), .driver_data = CHIP_VERDE|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6835), .driver_data = CHIP_VERDE|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6837), .driver_data = CHIP_VERDE|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6838), .driver_data = CHIP_VERDE|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6839), .driver_data = CHIP_VERDE|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x683B), .driver_data = CHIP_VERDE|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x683D), .driver_data = CHIP_VERDE|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x683F), .driver_data = CHIP_VERDE|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6840), .driver_data = CHIP_TURKS|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6841), .driver_data = CHIP_TURKS|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6842), .driver_data = CHIP_TURKS|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6843), .driver_data = CHIP_TURKS|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6849), .driver_data = CHIP_TURKS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x684C), .driver_data = CHIP_PITCAIRN|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6850), .driver_data = CHIP_TURKS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6858), .driver_data = CHIP_TURKS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6859), .driver_data = CHIP_TURKS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6880), .driver_data = CHIP_CYPRESS|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6888), .driver_data = CHIP_CYPRESS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6889), .driver_data = CHIP_CYPRESS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x688A), .driver_data = CHIP_CYPRESS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x688C), .driver_data = CHIP_CYPRESS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x688D), .driver_data = CHIP_CYPRESS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6898), .driver_data = CHIP_CYPRESS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x6899), .driver_data = CHIP_CYPRESS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x689b), .driver_data = CHIP_CYPRESS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x689c), .driver_data = CHIP_HEMLOCK|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x689d), .driver_data = CHIP_HEMLOCK|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x689e), .driver_data = CHIP_CYPRESS|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x68a0), .driver_data = CHIP_JUNIPER|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x68a1), .driver_data = CHIP_JUNIPER|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x68a8), .driver_data = CHIP_JUNIPER|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x68a9), .driver_data = CHIP_JUNIPER|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x68b0), .driver_data = CHIP_JUNIPER|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x68b8), .driver_data = CHIP_JUNIPER|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x68b9), .driver_data = CHIP_JUNIPER|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x68ba), .driver_data = CHIP_JUNIPER|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x68be), .driver_data = CHIP_JUNIPER|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x68bf), .driver_data = CHIP_JUNIPER|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x68c0), .driver_data = CHIP_REDWOOD|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x68c1), .driver_data = CHIP_REDWOOD|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x68c7), .driver_data = CHIP_REDWOOD|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x68c8), .driver_data = CHIP_REDWOOD|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x68c9), .driver_data = CHIP_REDWOOD|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x68d8), .driver_data = CHIP_REDWOOD|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x68d9), .driver_data = CHIP_REDWOOD|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x68da), .driver_data = CHIP_REDWOOD|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x68de), .driver_data = CHIP_REDWOOD|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x68e0), .driver_data = CHIP_CEDAR|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x68e1), .driver_data = CHIP_CEDAR|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x68e4), .driver_data = CHIP_CEDAR|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x68e5), .driver_data = CHIP_CEDAR|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x68e8), .driver_data = CHIP_CEDAR|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x68e9), .driver_data = CHIP_CEDAR|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x68f1), .driver_data = CHIP_CEDAR|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x68f2), .driver_data = CHIP_CEDAR|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x68f8), .driver_data = CHIP_CEDAR|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x68f9), .driver_data = CHIP_CEDAR|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x68fa), .driver_data = CHIP_CEDAR|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x68fe), .driver_data = CHIP_CEDAR|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7100), .driver_data = CHIP_R520|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7101), .driver_data = CHIP_R520|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7102), .driver_data = CHIP_R520|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7103), .driver_data = CHIP_R520|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7104), .driver_data = CHIP_R520|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7105), .driver_data = CHIP_R520|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7106), .driver_data = CHIP_R520|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7108), .driver_data = CHIP_R520|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7109), .driver_data = CHIP_R520|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x710A), .driver_data = CHIP_R520|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x710B), .driver_data = CHIP_R520|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x710C), .driver_data = CHIP_R520|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x710E), .driver_data = CHIP_R520|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x710F), .driver_data = CHIP_R520|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7140), .driver_data = CHIP_RV515|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7141), .driver_data = CHIP_RV515|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7142), .driver_data = CHIP_RV515|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7143), .driver_data = CHIP_RV515|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7144), .driver_data = CHIP_RV515|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7145), .driver_data = CHIP_RV515|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7146), .driver_data = CHIP_RV515|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7147), .driver_data = CHIP_RV515|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7149), .driver_data = CHIP_RV515|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x714A), .driver_data = CHIP_RV515|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x714B), .driver_data = CHIP_RV515|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x714C), .driver_data = CHIP_RV515|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x714D), .driver_data = CHIP_RV515|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x714E), .driver_data = CHIP_RV515|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x714F), .driver_data = CHIP_RV515|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7151), .driver_data = CHIP_RV515|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7152), .driver_data = CHIP_RV515|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7153), .driver_data = CHIP_RV515|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x715E), .driver_data = CHIP_RV515|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x715F), .driver_data = CHIP_RV515|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7180), .driver_data = CHIP_RV515|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7181), .driver_data = CHIP_RV515|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7183), .driver_data = CHIP_RV515|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7186), .driver_data = CHIP_RV515|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7187), .driver_data = CHIP_RV515|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7188), .driver_data = CHIP_RV515|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x718A), .driver_data = CHIP_RV515|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x718B), .driver_data = CHIP_RV515|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x718C), .driver_data = CHIP_RV515|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x718D), .driver_data = CHIP_RV515|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x718F), .driver_data = CHIP_RV515|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7193), .driver_data = CHIP_RV515|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7196), .driver_data = CHIP_RV515|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x719B), .driver_data = CHIP_RV515|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x719F), .driver_data = CHIP_RV515|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x71C0), .driver_data = CHIP_RV530|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x71C1), .driver_data = CHIP_RV530|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x71C2), .driver_data = CHIP_RV530|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x71C3), .driver_data = CHIP_RV530|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x71C4), .driver_data = CHIP_RV530|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x71C5), .driver_data = CHIP_RV530|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x71C6), .driver_data = CHIP_RV530|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x71C7), .driver_data = CHIP_RV530|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x71CD), .driver_data = CHIP_RV530|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x71CE), .driver_data = CHIP_RV530|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x71D2), .driver_data = CHIP_RV530|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x71D4), .driver_data = CHIP_RV530|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x71D5), .driver_data = CHIP_RV530|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x71D6), .driver_data = CHIP_RV530|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x71DA), .driver_data = CHIP_RV530|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x71DE), .driver_data = CHIP_RV530|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7200), .driver_data = CHIP_RV515|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7210), .driver_data = CHIP_RV515|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7211), .driver_data = CHIP_RV515|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7240), .driver_data = CHIP_R580|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7243), .driver_data = CHIP_R580|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7244), .driver_data = CHIP_R580|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7245), .driver_data = CHIP_R580|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7246), .driver_data = CHIP_R580|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7247), .driver_data = CHIP_R580|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7248), .driver_data = CHIP_R580|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7249), .driver_data = CHIP_R580|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x724A), .driver_data = CHIP_R580|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x724B), .driver_data = CHIP_R580|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x724C), .driver_data = CHIP_R580|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x724D), .driver_data = CHIP_R580|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x724E), .driver_data = CHIP_R580|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x724F), .driver_data = CHIP_R580|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7280), .driver_data = CHIP_RV570|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7281), .driver_data = CHIP_RV560|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7283), .driver_data = CHIP_RV560|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7284), .driver_data = CHIP_R580|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7287), .driver_data = CHIP_RV560|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7288), .driver_data = CHIP_RV570|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7289), .driver_data = CHIP_RV570|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x728B), .driver_data = CHIP_RV570|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x728C), .driver_data = CHIP_RV570|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7290), .driver_data = CHIP_RV560|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7291), .driver_data = CHIP_RV560|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7293), .driver_data = CHIP_RV560|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7297), .driver_data = CHIP_RV560|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7834), .driver_data = CHIP_RS300|RADEON_IS_IGP|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7835), .driver_data = CHIP_RS300|RADEON_IS_IGP|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x791e), .driver_data = CHIP_RS690|RADEON_IS_IGP|RADEON_NEW_MEMMAP|RADEON_IS_IGPGART },
	{ PCI_DEVICE(0x1002, 0x791f), .driver_data = CHIP_RS690|RADEON_IS_IGP|RADEON_NEW_MEMMAP|RADEON_IS_IGPGART },
	{ PCI_DEVICE(0x1002, 0x793f), .driver_data = CHIP_RS600|RADEON_IS_IGP|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7941), .driver_data = CHIP_RS600|RADEON_IS_IGP|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x7942), .driver_data = CHIP_RS600|RADEON_IS_IGP|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x796c), .driver_data = CHIP_RS740|RADEON_IS_IGP|RADEON_NEW_MEMMAP|RADEON_IS_IGPGART },
	{ PCI_DEVICE(0x1002, 0x796d), .driver_data = CHIP_RS740|RADEON_IS_IGP|RADEON_NEW_MEMMAP|RADEON_IS_IGPGART },
	{ PCI_DEVICE(0x1002, 0x796e), .driver_data = CHIP_RS740|RADEON_IS_IGP|RADEON_NEW_MEMMAP|RADEON_IS_IGPGART },
	{ PCI_DEVICE(0x1002, 0x796f), .driver_data = CHIP_RS740|RADEON_IS_IGP|RADEON_NEW_MEMMAP|RADEON_IS_IGPGART },
	{ PCI_DEVICE(0x1002, 0x9400), .driver_data = CHIP_R600|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9401), .driver_data = CHIP_R600|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9402), .driver_data = CHIP_R600|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9403), .driver_data = CHIP_R600|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9405), .driver_data = CHIP_R600|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x940A), .driver_data = CHIP_R600|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x940B), .driver_data = CHIP_R600|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x940F), .driver_data = CHIP_R600|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x94A0), .driver_data = CHIP_RV740|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x94A1), .driver_data = CHIP_RV740|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x94A3), .driver_data = CHIP_RV740|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x94B1), .driver_data = CHIP_RV740|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x94B3), .driver_data = CHIP_RV740|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x94B4), .driver_data = CHIP_RV740|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x94B5), .driver_data = CHIP_RV740|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x94B9), .driver_data = CHIP_RV740|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9440), .driver_data = CHIP_RV770|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9441), .driver_data = CHIP_RV770|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9442), .driver_data = CHIP_RV770|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9443), .driver_data = CHIP_RV770|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9444), .driver_data = CHIP_RV770|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9446), .driver_data = CHIP_RV770|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x944A), .driver_data = CHIP_RV770|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x944B), .driver_data = CHIP_RV770|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x944C), .driver_data = CHIP_RV770|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x944E), .driver_data = CHIP_RV770|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9450), .driver_data = CHIP_RV770|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9452), .driver_data = CHIP_RV770|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9456), .driver_data = CHIP_RV770|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x945A), .driver_data = CHIP_RV770|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x945B), .driver_data = CHIP_RV770|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x945E), .driver_data = CHIP_RV770|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9460), .driver_data = CHIP_RV770|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9462), .driver_data = CHIP_RV770|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x946A), .driver_data = CHIP_RV770|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x946B), .driver_data = CHIP_RV770|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x947A), .driver_data = CHIP_RV770|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x947B), .driver_data = CHIP_RV770|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9480), .driver_data = CHIP_RV730|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9487), .driver_data = CHIP_RV730|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9488), .driver_data = CHIP_RV730|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9489), .driver_data = CHIP_RV730|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x948A), .driver_data = CHIP_RV730|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x948F), .driver_data = CHIP_RV730|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9490), .driver_data = CHIP_RV730|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9491), .driver_data = CHIP_RV730|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9495), .driver_data = CHIP_RV730|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9498), .driver_data = CHIP_RV730|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x949C), .driver_data = CHIP_RV730|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x949E), .driver_data = CHIP_RV730|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x949F), .driver_data = CHIP_RV730|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x94C0), .driver_data = CHIP_RV610|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x94C1), .driver_data = CHIP_RV610|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x94C3), .driver_data = CHIP_RV610|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x94C4), .driver_data = CHIP_RV610|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x94C5), .driver_data = CHIP_RV610|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x94C6), .driver_data = CHIP_RV610|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x94C7), .driver_data = CHIP_RV610|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x94C8), .driver_data = CHIP_RV610|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x94C9), .driver_data = CHIP_RV610|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x94CB), .driver_data = CHIP_RV610|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x94CC), .driver_data = CHIP_RV610|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x94CD), .driver_data = CHIP_RV610|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9500), .driver_data = CHIP_RV670|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9501), .driver_data = CHIP_RV670|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9504), .driver_data = CHIP_RV670|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9505), .driver_data = CHIP_RV670|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9506), .driver_data = CHIP_RV670|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9507), .driver_data = CHIP_RV670|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9508), .driver_data = CHIP_RV670|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9509), .driver_data = CHIP_RV670|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x950F), .driver_data = CHIP_RV670|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9511), .driver_data = CHIP_RV670|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9515), .driver_data = CHIP_RV670|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9517), .driver_data = CHIP_RV670|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9519), .driver_data = CHIP_RV670|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9540), .driver_data = CHIP_RV710|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9541), .driver_data = CHIP_RV710|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9542), .driver_data = CHIP_RV710|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x954E), .driver_data = CHIP_RV710|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x954F), .driver_data = CHIP_RV710|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9552), .driver_data = CHIP_RV710|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9553), .driver_data = CHIP_RV710|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9555), .driver_data = CHIP_RV710|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9557), .driver_data = CHIP_RV710|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x955f), .driver_data = CHIP_RV710|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9580), .driver_data = CHIP_RV630|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9581), .driver_data = CHIP_RV630|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9583), .driver_data = CHIP_RV630|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9586), .driver_data = CHIP_RV630|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9587), .driver_data = CHIP_RV630|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9588), .driver_data = CHIP_RV630|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9589), .driver_data = CHIP_RV630|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x958A), .driver_data = CHIP_RV630|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x958B), .driver_data = CHIP_RV630|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x958C), .driver_data = CHIP_RV630|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x958D), .driver_data = CHIP_RV630|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x958E), .driver_data = CHIP_RV630|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x958F), .driver_data = CHIP_RV630|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9590), .driver_data = CHIP_RV635|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9591), .driver_data = CHIP_RV635|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9593), .driver_data = CHIP_RV635|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9595), .driver_data = CHIP_RV635|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9596), .driver_data = CHIP_RV635|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9597), .driver_data = CHIP_RV635|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9598), .driver_data = CHIP_RV635|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9599), .driver_data = CHIP_RV635|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x959B), .driver_data = CHIP_RV635|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x95C0), .driver_data = CHIP_RV620|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x95C2), .driver_data = CHIP_RV620|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x95C4), .driver_data = CHIP_RV620|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x95C5), .driver_data = CHIP_RV620|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x95C6), .driver_data = CHIP_RV620|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x95C7), .driver_data = CHIP_RV620|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x95C9), .driver_data = CHIP_RV620|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x95CC), .driver_data = CHIP_RV620|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x95CD), .driver_data = CHIP_RV620|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x95CE), .driver_data = CHIP_RV620|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x95CF), .driver_data = CHIP_RV620|RADEON_NEW_MEMMAP },
	{ PCI_DEVICE(0x1002, 0x9610), .driver_data = CHIP_RS780|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9611), .driver_data = CHIP_RS780|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9612), .driver_data = CHIP_RS780|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9613), .driver_data = CHIP_RS780|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9614), .driver_data = CHIP_RS780|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9615), .driver_data = CHIP_RS780|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9616), .driver_data = CHIP_RS780|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9640), .driver_data = CHIP_SUMO|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9641), .driver_data = CHIP_SUMO|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9642), .driver_data = CHIP_SUMO2|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9643), .driver_data = CHIP_SUMO2|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9644), .driver_data = CHIP_SUMO2|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9645), .driver_data = CHIP_SUMO2|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9647), .driver_data = CHIP_SUMO|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },\
	{ PCI_DEVICE(0x1002, 0x9648), .driver_data = CHIP_SUMO|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },\
	{ PCI_DEVICE(0x1002, 0x9649), .driver_data = CHIP_SUMO2|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },\
	{ PCI_DEVICE(0x1002, 0x964a), .driver_data = CHIP_SUMO|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x964b), .driver_data = CHIP_SUMO|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x964c), .driver_data = CHIP_SUMO|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x964e), .driver_data = CHIP_SUMO|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },\
	{ PCI_DEVICE(0x1002, 0x964f), .driver_data = CHIP_SUMO|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },\
	{ PCI_DEVICE(0x1002, 0x9710), .driver_data = CHIP_RS880|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9711), .driver_data = CHIP_RS880|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9712), .driver_data = CHIP_RS880|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9713), .driver_data = CHIP_RS880|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9714), .driver_data = CHIP_RS880|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9715), .driver_data = CHIP_RS880|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9802), .driver_data = CHIP_PALM|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9803), .driver_data = CHIP_PALM|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9804), .driver_data = CHIP_PALM|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9805), .driver_data = CHIP_PALM|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9806), .driver_data = CHIP_PALM|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9807), .driver_data = CHIP_PALM|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9808), .driver_data = CHIP_PALM|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9809), .driver_data = CHIP_PALM|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x980A), .driver_data = CHIP_PALM|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9830), .driver_data = CHIP_KABINI|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9831), .driver_data = CHIP_KABINI|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9832), .driver_data = CHIP_KABINI|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9833), .driver_data = CHIP_KABINI|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9834), .driver_data = CHIP_KABINI|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9835), .driver_data = CHIP_KABINI|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9836), .driver_data = CHIP_KABINI|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9837), .driver_data = CHIP_KABINI|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9838), .driver_data = CHIP_KABINI|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9839), .driver_data = CHIP_KABINI|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x983a), .driver_data = CHIP_KABINI|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x983b), .driver_data = CHIP_KABINI|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x983c), .driver_data = CHIP_KABINI|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x983d), .driver_data = CHIP_KABINI|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x983e), .driver_data = CHIP_KABINI|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x983f), .driver_data = CHIP_KABINI|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9850), .driver_data = CHIP_MULLINS|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9851), .driver_data = CHIP_MULLINS|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9852), .driver_data = CHIP_MULLINS|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9853), .driver_data = CHIP_MULLINS|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9854), .driver_data = CHIP_MULLINS|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9855), .driver_data = CHIP_MULLINS|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9856), .driver_data = CHIP_MULLINS|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9857), .driver_data = CHIP_MULLINS|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9858), .driver_data = CHIP_MULLINS|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9859), .driver_data = CHIP_MULLINS|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x985A), .driver_data = CHIP_MULLINS|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x985B), .driver_data = CHIP_MULLINS|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x985C), .driver_data = CHIP_MULLINS|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x985D), .driver_data = CHIP_MULLINS|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x985E), .driver_data = CHIP_MULLINS|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x985F), .driver_data = CHIP_MULLINS|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9900), .driver_data = CHIP_ARUBA|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9901), .driver_data = CHIP_ARUBA|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9903), .driver_data = CHIP_ARUBA|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9904), .driver_data = CHIP_ARUBA|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9905), .driver_data = CHIP_ARUBA|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9906), .driver_data = CHIP_ARUBA|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9907), .driver_data = CHIP_ARUBA|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9908), .driver_data = CHIP_ARUBA|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9909), .driver_data = CHIP_ARUBA|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x990A), .driver_data = CHIP_ARUBA|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x990B), .driver_data = CHIP_ARUBA|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x990C), .driver_data = CHIP_ARUBA|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x990D), .driver_data = CHIP_ARUBA|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x990E), .driver_data = CHIP_ARUBA|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x990F), .driver_data = CHIP_ARUBA|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9910), .driver_data = CHIP_ARUBA|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9913), .driver_data = CHIP_ARUBA|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9917), .driver_data = CHIP_ARUBA|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9918), .driver_data = CHIP_ARUBA|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9919), .driver_data = CHIP_ARUBA|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9990), .driver_data = CHIP_ARUBA|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9991), .driver_data = CHIP_ARUBA|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9992), .driver_data = CHIP_ARUBA|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9993), .driver_data = CHIP_ARUBA|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9994), .driver_data = CHIP_ARUBA|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9995), .driver_data = CHIP_ARUBA|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9996), .driver_data = CHIP_ARUBA|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9997), .driver_data = CHIP_ARUBA|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9998), .driver_data = CHIP_ARUBA|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x9999), .driver_data = CHIP_ARUBA|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x999A), .driver_data = CHIP_ARUBA|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x999B), .driver_data = CHIP_ARUBA|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x999C), .driver_data = CHIP_ARUBA|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x999D), .driver_data = CHIP_ARUBA|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x99A0), .driver_data = CHIP_ARUBA|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x99A2), .driver_data = CHIP_ARUBA|RADEON_IS_MOBILITY|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ PCI_DEVICE(0x1002, 0x99A4), .driver_data = CHIP_ARUBA|RADEON_NEW_MEMMAP|RADEON_IS_IGP },
	{ }
};
MODULE_DEVICE_TABLE(pci, pciidlist);

static const struct drm_driver kms_driver;

static bool radeon_support_enabled(struct device *dev,
				   const enum radeon_family family)
{
	const char *gen;
	int module_param = -1;
	bool amdgpu_support_built = IS_ENABLED(CONFIG_DRM_AMDGPU);
	bool support_by_default = true;

	switch (family) {
	case CHIP_TAHITI:
	case CHIP_PITCAIRN:
	case CHIP_VERDE:
	case CHIP_OLAND:
	case CHIP_HAINAN:
		gen = "SI";
		module_param = radeon_si_support;
		amdgpu_support_built &= IS_ENABLED(CONFIG_DRM_AMDGPU_SI);
		support_by_default = false;
		break;

	case CHIP_BONAIRE:
	case CHIP_HAWAII:
	case CHIP_KAVERI:
	case CHIP_KABINI:
	case CHIP_MULLINS:
		gen = "CIK";
		module_param = radeon_cik_support;
		amdgpu_support_built &= IS_ENABLED(CONFIG_DRM_AMDGPU_CIK);
		support_by_default = false;
		break;

	default:
		/* All other chips are supported by radeon only */
		return true;
	}

	if ((module_param == -1 && (support_by_default || !amdgpu_support_built)) ||
	    module_param == 1)
		return true;

	if (!module_param)
		dev_info(dev, "%s support disabled by module param\n", gen);

	return false;
}

static int radeon_pci_probe(struct pci_dev *pdev,
			    const struct pci_device_id *ent)
{
	unsigned long flags = 0;
	struct drm_device *ddev;
	struct radeon_device *rdev;
	struct device *dev = &pdev->dev;
	const struct drm_format_info *format;
	int ret;

	if (!ent)
		return -ENODEV; /* Avoid NULL-ptr deref in drm_get_pci_dev */

	flags = ent->driver_data;

	if (!radeon_support_enabled(dev, flags & RADEON_FAMILY_MASK))
		return -ENODEV;

	if (vga_switcheroo_client_probe_defer(pdev))
		return -EPROBE_DEFER;

	/* Get rid of things like offb */
	ret = aperture_remove_conflicting_pci_devices(pdev, kms_driver.name);
	if (ret)
		return ret;

	rdev = devm_drm_dev_alloc(dev, &kms_driver, typeof(*rdev), ddev);
	if (IS_ERR(rdev))
		return PTR_ERR(rdev);

	rdev->dev = dev;
	rdev->pdev = pdev;
	ddev = rdev_to_drm(rdev);
	ddev->dev_private = rdev;

	ret = pci_enable_device(pdev);
	if (ret)
		return ret;

	pci_set_drvdata(pdev, ddev);

	ret = radeon_driver_load_kms(ddev, flags);
	if (ret)
		goto err;

	ret = drm_dev_register(ddev, flags);
	if (ret)
		goto err;

	if (rdev->mc.real_vram_size <= (8 * 1024 * 1024))
		format = drm_format_info(DRM_FORMAT_C8);
	else if (ASIC_IS_RN50(rdev) || rdev->mc.real_vram_size <= (32 * 1024 * 1024))
		format = drm_format_info(DRM_FORMAT_RGB565);
	else
		format = NULL;

	drm_client_setup(ddev, format);

	return 0;

err:
	pci_disable_device(pdev);
	return ret;
}

static void
radeon_pci_shutdown(struct pci_dev *pdev)
{
#if defined(CONFIG_PPC64) || defined(CONFIG_MACH_LOONGSON64)
	/*
	 * Some adapters need to be suspended before a
	 * shutdown occurs in order to prevent an error
	 * during kexec, shutdown or reboot.
	 * Make this power and Loongson specific because
	 * it breaks some other boards.
	 */
	radeon_suspend_kms(pci_get_drvdata(pdev), true, true, false);
#endif
}

static int radeon_pmops_suspend(struct device *dev)
{
	struct drm_device *drm_dev = dev_get_drvdata(dev);

	return radeon_suspend_kms(drm_dev, true, true, false);
}

static int radeon_pmops_resume(struct device *dev)
{
	struct drm_device *drm_dev = dev_get_drvdata(dev);

	/* GPU comes up enabled by the bios on resume */
	if (radeon_is_px(drm_dev)) {
		pm_runtime_disable(dev);
		pm_runtime_set_active(dev);
		pm_runtime_enable(dev);
	}

	return radeon_resume_kms(drm_dev, true, true);
}

static int radeon_pmops_freeze(struct device *dev)
{
	struct drm_device *drm_dev = dev_get_drvdata(dev);

	return radeon_suspend_kms(drm_dev, false, true, true);
}

static int radeon_pmops_thaw(struct device *dev)
{
	struct drm_device *drm_dev = dev_get_drvdata(dev);

	return radeon_resume_kms(drm_dev, false, true);
}

static int radeon_pmops_runtime_suspend(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct drm_device *drm_dev = pci_get_drvdata(pdev);

	if (!radeon_is_px(drm_dev)) {
		pm_runtime_forbid(dev);
		return -EBUSY;
	}

	drm_dev->switch_power_state = DRM_SWITCH_POWER_CHANGING;
	drm_kms_helper_poll_disable(drm_dev);

	radeon_suspend_kms(drm_dev, false, false, false);
	pci_save_state(pdev);
	pci_disable_device(pdev);
	pci_ignore_hotplug(pdev);
	if (radeon_is_atpx_hybrid())
		pci_set_power_state(pdev, PCI_D3cold);
	else if (!radeon_has_atpx_dgpu_power_cntl())
		pci_set_power_state(pdev, PCI_D3hot);
	drm_dev->switch_power_state = DRM_SWITCH_POWER_DYNAMIC_OFF;

	return 0;
}

static int radeon_pmops_runtime_resume(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct drm_device *drm_dev = pci_get_drvdata(pdev);
	int ret;

	if (!radeon_is_px(drm_dev))
		return -EINVAL;

	drm_dev->switch_power_state = DRM_SWITCH_POWER_CHANGING;

	if (radeon_is_atpx_hybrid() ||
	    !radeon_has_atpx_dgpu_power_cntl())
		pci_set_power_state(pdev, PCI_D0);
	pci_restore_state(pdev);
	ret = pci_enable_device(pdev);
	if (ret)
		return ret;
	pci_set_master(pdev);

	ret = radeon_resume_kms(drm_dev, false, false);
	drm_kms_helper_poll_enable(drm_dev);
	drm_dev->switch_power_state = DRM_SWITCH_POWER_ON;
	return 0;
}

static int radeon_pmops_runtime_idle(struct device *dev)
{
	struct drm_device *drm_dev = dev_get_drvdata(dev);
	struct drm_crtc *crtc;

	if (!radeon_is_px(drm_dev)) {
		pm_runtime_forbid(dev);
		return -EBUSY;
	}

	list_for_each_entry(crtc, &drm_dev->mode_config.crtc_list, head) {
		if (crtc->enabled) {
			DRM_DEBUG_DRIVER("failing to power off - crtc active\n");
			return -EBUSY;
		}
	}

	pm_runtime_autosuspend(dev);
	/* we don't want the main rpm_idle to call suspend - we want to autosuspend */
	return 1;
}

long radeon_drm_ioctl(struct file *filp,
		      unsigned int cmd, unsigned long arg)
{
	struct drm_file *file_priv = filp->private_data;
	struct drm_device *dev;
	long ret;

	dev = file_priv->minor->dev;
	ret = pm_runtime_get_sync(dev->dev);
	if (ret < 0) {
		pm_runtime_put_autosuspend(dev->dev);
		return ret;
	}

	ret = drm_ioctl(filp, cmd, arg);

	pm_runtime_put_autosuspend(dev->dev);
	return ret;
}

#ifdef CONFIG_COMPAT
static long radeon_kms_compat_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	unsigned int nr = DRM_IOCTL_NR(cmd);

	if (nr < DRM_COMMAND_BASE)
		return drm_compat_ioctl(filp, cmd, arg);

	return radeon_drm_ioctl(filp, cmd, arg);
}
#endif

static const struct dev_pm_ops radeon_pm_ops = {
	.suspend = radeon_pmops_suspend,
	.resume = radeon_pmops_resume,
	.freeze = radeon_pmops_freeze,
	.thaw = radeon_pmops_thaw,
	.poweroff = radeon_pmops_freeze,
	.restore = radeon_pmops_resume,
	.runtime_suspend = radeon_pmops_runtime_suspend,
	.runtime_resume = radeon_pmops_runtime_resume,
	.runtime_idle = radeon_pmops_runtime_idle,
};

static const struct file_operations radeon_driver_kms_fops = {
	.owner = THIS_MODULE,
	.open = drm_open,
	.release = drm_release,
	.unlocked_ioctl = radeon_drm_ioctl,
	.mmap = drm_gem_mmap,
	.poll = drm_poll,
	.read = drm_read,
#ifdef CONFIG_COMPAT
	.compat_ioctl = radeon_kms_compat_ioctl,
#endif
	.fop_flags = FOP_UNSIGNED_OFFSET,
};

static const struct drm_ioctl_desc radeon_ioctls_kms[] = {
	DRM_IOCTL_DEF_DRV(RADEON_CP_INIT, drm_invalid_op, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF_DRV(RADEON_CP_START, drm_invalid_op, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF_DRV(RADEON_CP_STOP, drm_invalid_op, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF_DRV(RADEON_CP_RESET, drm_invalid_op, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF_DRV(RADEON_CP_IDLE, drm_invalid_op, DRM_AUTH),
	DRM_IOCTL_DEF_DRV(RADEON_CP_RESUME, drm_invalid_op, DRM_AUTH),
	DRM_IOCTL_DEF_DRV(RADEON_RESET, drm_invalid_op, DRM_AUTH),
	DRM_IOCTL_DEF_DRV(RADEON_FULLSCREEN, drm_invalid_op, DRM_AUTH),
	DRM_IOCTL_DEF_DRV(RADEON_SWAP, drm_invalid_op, DRM_AUTH),
	DRM_IOCTL_DEF_DRV(RADEON_CLEAR, drm_invalid_op, DRM_AUTH),
	DRM_IOCTL_DEF_DRV(RADEON_VERTEX, drm_invalid_op, DRM_AUTH),
	DRM_IOCTL_DEF_DRV(RADEON_INDICES, drm_invalid_op, DRM_AUTH),
	DRM_IOCTL_DEF_DRV(RADEON_TEXTURE, drm_invalid_op, DRM_AUTH),
	DRM_IOCTL_DEF_DRV(RADEON_STIPPLE, drm_invalid_op, DRM_AUTH),
	DRM_IOCTL_DEF_DRV(RADEON_INDIRECT, drm_invalid_op, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF_DRV(RADEON_VERTEX2, drm_invalid_op, DRM_AUTH),
	DRM_IOCTL_DEF_DRV(RADEON_CMDBUF, drm_invalid_op, DRM_AUTH),
	DRM_IOCTL_DEF_DRV(RADEON_GETPARAM, drm_invalid_op, DRM_AUTH),
	DRM_IOCTL_DEF_DRV(RADEON_FLIP, drm_invalid_op, DRM_AUTH),
	DRM_IOCTL_DEF_DRV(RADEON_ALLOC, drm_invalid_op, DRM_AUTH),
	DRM_IOCTL_DEF_DRV(RADEON_FREE, drm_invalid_op, DRM_AUTH),
	DRM_IOCTL_DEF_DRV(RADEON_INIT_HEAP, drm_invalid_op, DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY),
	DRM_IOCTL_DEF_DRV(RADEON_IRQ_EMIT, drm_invalid_op, DRM_AUTH),
	DRM_IOCTL_DEF_DRV(RADEON_IRQ_WAIT, drm_invalid_op, DRM_AUTH),
	DRM_IOCTL_DEF_DRV(RADEON_SETPARAM, drm_invalid_op, DRM_AUTH),
	DRM_IOCTL_DEF_DRV(RADEON_SURF_ALLOC, drm_invalid_op, DRM_AUTH),
	DRM_IOCTL_DEF_DRV(RADEON_SURF_FREE, drm_invalid_op, DRM_AUTH),
	/* KMS */
	DRM_IOCTL_DEF_DRV(RADEON_GEM_INFO, radeon_gem_info_ioctl, DRM_AUTH|DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(RADEON_GEM_CREATE, radeon_gem_create_ioctl, DRM_AUTH|DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(RADEON_GEM_MMAP, radeon_gem_mmap_ioctl, DRM_AUTH|DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(RADEON_GEM_SET_DOMAIN, radeon_gem_set_domain_ioctl, DRM_AUTH|DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(RADEON_GEM_WAIT_IDLE, radeon_gem_wait_idle_ioctl, DRM_AUTH|DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(RADEON_CS, radeon_cs_ioctl, DRM_AUTH|DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(RADEON_INFO, radeon_info_ioctl, DRM_AUTH|DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(RADEON_GEM_SET_TILING, radeon_gem_set_tiling_ioctl, DRM_AUTH|DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(RADEON_GEM_GET_TILING, radeon_gem_get_tiling_ioctl, DRM_AUTH|DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(RADEON_GEM_BUSY, radeon_gem_busy_ioctl, DRM_AUTH|DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(RADEON_GEM_VA, radeon_gem_va_ioctl, DRM_AUTH|DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(RADEON_GEM_OP, radeon_gem_op_ioctl, DRM_AUTH|DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(RADEON_GEM_USERPTR, radeon_gem_userptr_ioctl, DRM_AUTH|DRM_RENDER_ALLOW),
};

static const struct drm_driver kms_driver = {
	.driver_features =
	    DRIVER_GEM | DRIVER_RENDER | DRIVER_MODESET,
	.open = radeon_driver_open_kms,
	.postclose = radeon_driver_postclose_kms,
	.unload = radeon_driver_unload_kms,
	.ioctls = radeon_ioctls_kms,
	.num_ioctls = ARRAY_SIZE(radeon_ioctls_kms),
	.dumb_create = radeon_mode_dumb_create,
	.dumb_map_offset = radeon_mode_dumb_mmap,
	.fops = &radeon_driver_kms_fops,

	.gem_prime_import_sg_table = radeon_gem_prime_import_sg_table,

	RADEON_FBDEV_DRIVER_OPS,

	.name = DRIVER_NAME,
	.desc = DRIVER_DESC,
	.major = KMS_DRIVER_MAJOR,
	.minor = KMS_DRIVER_MINOR,
	.patchlevel = KMS_DRIVER_PATCHLEVEL,
};

static struct pci_driver radeon_kms_pci_driver = {
	.name = DRIVER_NAME,
	.id_table = pciidlist,
	.probe = radeon_pci_probe,
	.shutdown = radeon_pci_shutdown,
	.driver.pm = &radeon_pm_ops,
};

static int __init radeon_module_init(void)
{
	if (drm_firmware_drivers_only() && radeon_modeset == -1)
		radeon_modeset = 0;

	if (radeon_modeset == 0)
		return -EINVAL;

	DRM_INFO("radeon kernel modesetting enabled.\n");
	radeon_register_atpx_handler();

	return pci_register_driver(&radeon_kms_pci_driver);
}

static void __exit radeon_module_exit(void)
{
	pci_unregister_driver(&radeon_kms_pci_driver);
	radeon_unregister_atpx_handler();
	mmu_notifier_synchronize();
}

module_init(radeon_module_init);
module_exit(radeon_module_exit);

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL and additional rights");
