/*
 * Copyright 2026 Advanced Micro Devices, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 */
#include <linux/firmware.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/pci.h>

#include "amdgpu.h"
#include "amdgpu_ih.h"
#include "amdgpu_ucode.h"
#include "amdgpu_psp.h"
#include "amdgpu_smu.h"
#include "atom.h"
#include "amd_pcie.h"

#include "gc/gc_13_0_1_offset.h"
#include "gc/gc_13_0_1_sh_mask.h"
#include "mp/mp_15_0_3_offset.h"

#include "soc15.h"
#include "soc15_common.h"
#include "soc_v2_0.h"
#include "mxgpu_nv.h"

static const struct amd_ip_funcs soc_v2_0_common_ip_funcs;

static u32 soc_v2_0_get_config_memsize(struct amdgpu_device *adev)
{
	return adev->nbio.funcs->get_memsize(adev);
}

static u32 soc_v2_0_get_xclk(struct amdgpu_device *adev)
{
	return adev->clock.spll.reference_freq;
}

void soc_v2_0_grbm_select(struct amdgpu_device *adev,
			  u32 me, u32 pipe, u32 queue, u32 vmid)
{
	u32 grbm_gfx_cntl = 0;
	grbm_gfx_cntl = REG_SET_FIELD(grbm_gfx_cntl, GRBM_GFX_CNTL, PIPEID, pipe);
	grbm_gfx_cntl = REG_SET_FIELD(grbm_gfx_cntl, GRBM_GFX_CNTL, MEID, me);
	grbm_gfx_cntl = REG_SET_FIELD(grbm_gfx_cntl, GRBM_GFX_CNTL, VMID, vmid);
	grbm_gfx_cntl = REG_SET_FIELD(grbm_gfx_cntl, GRBM_GFX_CNTL, QUEUEID, queue);

	WREG32_SOC15(GC, 0, regGRBM_GFX_CNTL, grbm_gfx_cntl);
}

static struct soc15_allowed_register_entry soc_v2_0_allowed_read_registers[] = {
	{ SOC15_REG_ENTRY(GC, 0, regGRBM_STATUS)},
	{ SOC15_REG_ENTRY(GC, 0, regGRBM_STATUS2)},
	{ SOC15_REG_ENTRY(GC, 0, regGRBM_STATUS_SE0)},
	{ SOC15_REG_ENTRY(GC, 0, regGRBM_STATUS_SE1)},
	{ SOC15_REG_ENTRY(GC, 0, regGRBM_STATUS_SE2)},
	{ SOC15_REG_ENTRY(GC, 0, regGRBM_STATUS_SE3)},
	{ SOC15_REG_ENTRY(SDMA0, 0, regSDMA0_SDMA_STATUS_REG)},
	{ SOC15_REG_ENTRY(SDMA1, 0, regSDMA1_SDMA_STATUS_REG)},
	{ SOC15_REG_ENTRY(SDMA2, 0, regSDMA2_SDMA_STATUS_REG)},
	{ SOC15_REG_ENTRY(SDMA3, 0, regSDMA3_SDMA_STATUS_REG)},
	{ SOC15_REG_ENTRY(GC, 0, regCP_STAT)},
	{ SOC15_REG_ENTRY(GC, 0, regCP_STALLED_STAT1)},
	{ SOC15_REG_ENTRY(GC, 0, regCP_STALLED_STAT2)},
	{ SOC15_REG_ENTRY(GC, 0, regCP_STALLED_STAT3)},
	{ SOC15_REG_ENTRY(GC, 0, regCP_CPF_BUSY_STAT)},
	{ SOC15_REG_ENTRY(GC, 0, regCP_CPF_STALLED_STAT1)},
	{ SOC15_REG_ENTRY(GC, 0, regCP_CPF_STATUS)},
	{ SOC15_REG_ENTRY(GC, 0, regCP_CPC_BUSY_STAT)},
	{ SOC15_REG_ENTRY(GC, 0, regCP_CPC_STALLED_STAT1)},
	{ SOC15_REG_ENTRY(GC, 0, regCP_CPC_STATUS)},
	{ SOC15_REG_ENTRY(GC, 0, regGB_ADDR_CONFIG)},
};

static uint32_t soc_v2_0_read_indexed_register(struct amdgpu_device *adev,
					       u32 se_num,
					       u32 sh_num,
					       u32 reg_offset)
{
	uint32_t val;

	mutex_lock(&adev->grbm_idx_mutex);
	if (se_num != 0xffffffff || sh_num != 0xffffffff)
		amdgpu_gfx_select_se_sh(adev, se_num, sh_num, 0xffffffff, 0);

	val = RREG32(reg_offset);

	if (se_num != 0xffffffff || sh_num != 0xffffffff)
		amdgpu_gfx_select_se_sh(adev, 0xffffffff, 0xffffffff, 0xffffffff, 0);
	mutex_unlock(&adev->grbm_idx_mutex);
	return val;
}

static uint32_t soc_v2_0_get_register_value(struct amdgpu_device *adev,
					    bool indexed, u32 se_num,
					    u32 sh_num, u32 reg_offset)
{
	if (indexed) {
		return soc_v2_0_read_indexed_register(adev, se_num, sh_num, reg_offset);
	} else {
		if (reg_offset == SOC15_REG_OFFSET(GC, 0, regGB_ADDR_CONFIG) &&
		    adev->gfx.config.gb_addr_config)
			return adev->gfx.config.gb_addr_config;
		return RREG32(reg_offset);
	}
}

static int soc_v2_0_read_register(struct amdgpu_device *adev, u32 se_num,
				  u32 sh_num, u32 reg_offset, u32 *value)
{
	uint32_t i;
	struct soc15_allowed_register_entry  *en;

	*value = 0;
	for (i = 0; i < ARRAY_SIZE(soc_v2_0_allowed_read_registers); i++) {
		en = &soc_v2_0_allowed_read_registers[i];
		if (!adev->reg_offset[en->hwip][en->inst])
			continue;
		else if (reg_offset != (adev->reg_offset[en->hwip][en->inst][en->seg]
					+ en->reg_offset))
			continue;

		*value = soc_v2_0_get_register_value(adev,
				soc_v2_0_allowed_read_registers[i].grbm_indexed,
				se_num, sh_num, reg_offset);
		return 0;
	}
	return -EINVAL;
}

static enum amd_reset_method soc_v2_0_asic_reset_method(struct amdgpu_device *adev)
{
	if (amdgpu_reset_method == AMD_RESET_METHOD_MODE0 ||
	    amdgpu_reset_method == AMD_RESET_METHOD_MODE2 ||
	    amdgpu_reset_method == AMD_RESET_METHOD_BACO)
		return amdgpu_reset_method;

	if (amdgpu_reset_method != -1)
		dev_warn(adev->dev,
			 "Specified reset method:%d isn't supported, using AUTO instead.\n",
			 amdgpu_reset_method);

	switch (amdgpu_ip_version(adev, MP1_HWIP, 0)) {
	case IP_VERSION(15, 0, 3):
		return AMD_RESET_METHOD_MODE0;
	default:
		if (amdgpu_dpm_is_baco_supported(adev))
			return AMD_RESET_METHOD_BACO;
		else
			return AMD_RESET_METHOD_MODE0;
	}
}

static int soc_v2_0_asic_reset(struct amdgpu_device *adev)
{
	int ret = 0;

	switch (soc_v2_0_asic_reset_method(adev)) {
	case AMD_RESET_METHOD_PCI:
		dev_info(adev->dev, "PCI reset\n");
		ret = amdgpu_device_pci_reset(adev);
		break;
	case AMD_RESET_METHOD_BACO:
		dev_info(adev->dev, "BACO reset\n");
		ret = amdgpu_dpm_baco_reset(adev);
		break;
	case AMD_RESET_METHOD_MODE2:
		dev_info(adev->dev, "MODE2 reset\n");
		ret = amdgpu_dpm_mode2_reset(adev);
		break;
	default:
		dev_info(adev->dev, "MODE0 reset\n");
		/*TODO: replace mode1 with mode0 */
		ret = amdgpu_device_mode1_reset(adev);
		break;
	}

	return ret;
}

const struct amdgpu_ip_block_version soc_v2_0_common_ip_block = {
	.type = AMD_IP_BLOCK_TYPE_COMMON,
	.major = 2,
	.minor = 0,
	.rev = 0,
	.funcs = &soc_v2_0_common_ip_funcs,
};

static bool soc_v2_0_need_reset_on_init(struct amdgpu_device *adev)
{
	u32 sol_reg;

	if (adev->flags & AMD_IS_APU)
		return false;

	/*
	 * Check the sOS sign-of-life register to confirm that the system
	 * driver and sOS are already loaded.
	 */

	sol_reg = RREG32_SOC15(MP0, 0,
				regMPASP_PCRU0_MPASP_C2PMSG_81);
	if (sol_reg)
		return true;

	return false;
}

static void soc_v2_0_init_doorbell_index(struct amdgpu_device *adev)
{
	adev->doorbell_index.kiq = AMDGPU_NAVI10_DOORBELL_KIQ;
	adev->doorbell_index.mec_ring0 = AMDGPU_NAVI10_DOORBELL_MEC_RING0;
	adev->doorbell_index.mec_ring1 = AMDGPU_NAVI10_DOORBELL_MEC_RING1;
	adev->doorbell_index.mec_ring2 = AMDGPU_NAVI10_DOORBELL_MEC_RING2;
	adev->doorbell_index.mec_ring3 = AMDGPU_NAVI10_DOORBELL_MEC_RING3;
	adev->doorbell_index.mec_ring4 = AMDGPU_NAVI10_DOORBELL_MEC_RING4;
	adev->doorbell_index.mec_ring5 = AMDGPU_NAVI10_DOORBELL_MEC_RING5;
	adev->doorbell_index.mec_ring6 = AMDGPU_NAVI10_DOORBELL_MEC_RING6;
	adev->doorbell_index.mec_ring7 = AMDGPU_NAVI10_DOORBELL_MEC_RING7;
	adev->doorbell_index.userqueue_start = AMDGPU_NAVI10_DOORBELL_USERQUEUE_START;
	adev->doorbell_index.userqueue_end = AMDGPU_NAVI10_DOORBELL_USERQUEUE_END;
	adev->doorbell_index.gfx_ring0 = AMDGPU_NAVI10_DOORBELL_GFX_RING0;
	adev->doorbell_index.gfx_ring1 = AMDGPU_NAVI10_DOORBELL_GFX_RING1;
	adev->doorbell_index.gfx_userqueue_start =
		AMDGPU_NAVI10_DOORBELL_GFX_USERQUEUE_START;
	adev->doorbell_index.gfx_userqueue_end =
		AMDGPU_NAVI10_DOORBELL_GFX_USERQUEUE_END;
	adev->doorbell_index.mes_ring0 = AMDGPU_NAVI10_DOORBELL_MES_RING0;
	adev->doorbell_index.mes_ring1 = AMDGPU_NAVI10_DOORBELL_MES_RING1;
	adev->doorbell_index.sdma_engine[0] = AMDGPU_NAVI10_DOORBELL_sDMA_ENGINE0;
	adev->doorbell_index.sdma_engine[1] = AMDGPU_NAVI10_DOORBELL_sDMA_ENGINE1;
	adev->doorbell_index.sdma_engine[2] = AMDGPU_NAVI10_DOORBELL_sDMA_ENGINE2;
	adev->doorbell_index.sdma_engine[3] = AMDGPU_NAVI10_DOORBELL_sDMA_ENGINE3;
	adev->doorbell_index.ih = AMDGPU_NAVI10_DOORBELL_IH;
	adev->doorbell_index.vcn.vcn_ring0_1 = AMDGPU_NAVI10_DOORBELL64_VCN0_1;
	adev->doorbell_index.vcn.vcn_ring2_3 = AMDGPU_NAVI10_DOORBELL64_VCN2_3;
	adev->doorbell_index.vcn.vcn_ring4_5 = AMDGPU_NAVI10_DOORBELL64_VCN4_5;
	adev->doorbell_index.vcn.vcn_ring6_7 = AMDGPU_NAVI10_DOORBELL64_VCN6_7;
	adev->doorbell_index.vpe_ring = AMDGPU_NAVI10_DOORBELL64_VPE;
	adev->doorbell_index.first_non_cp = AMDGPU_NAVI10_DOORBELL64_FIRST_NON_CP;
	adev->doorbell_index.last_non_cp = AMDGPU_NAVI10_DOORBELL64_LAST_NON_CP;

	adev->doorbell_index.max_assignment = AMDGPU_NAVI10_DOORBELL_MAX_ASSIGNMENT << 1;
	adev->doorbell_index.sdma_doorbell_range = 20;
}

static int soc_v2_0_update_umd_stable_pstate(struct amdgpu_device *adev,
					     bool enter)
{
	if (enter)
		amdgpu_gfx_rlc_enter_safe_mode(adev, 0);
	else
		amdgpu_gfx_rlc_exit_safe_mode(adev, 0);

	if (adev->gfx.funcs &&
	    adev->gfx.funcs->update_perfmon_mgcg)
		adev->gfx.funcs->update_perfmon_mgcg(adev, !enter);

	return 0;
}

static void soc_v2_0_get_fw_reserved_info(struct amdgpu_device *adev,
					  u64 *reserve_size,
					  u64 *offset)
{
	struct mem_reserved_info_table_v1_0 *table =
		adev->discovery.mem_reserved_table;
	u64 resv_start = U64_MAX, resv_end = 0;
	u64 vram_base, vram_end, start, end, size;
	u32 list_num, id, i;

	if (!table) {
		dev_warn(adev->dev, "MEM_RESERVED_INFO table not available\n");
		return;
	}

	vram_base = adev->gmc.vram_start - adev->mmhub.funcs->get_fb_location(adev);
	vram_end = vram_base + adev->gmc.real_vram_size;

	list_num = min_t(u32, le32_to_cpu(table->list_num), MAX_MEM_REGION_NUM);
	for (i = 0; i < list_num; i++) {
		id = le32_to_cpu(table->list[i].reserved_region_id);
		size = le64_to_cpu(table->list[i].reserved_region_size);
		start = le64_to_cpu(table->list[i].reserved_region_start);

		if (id == NO_RESERVED_REGION_ID ||
		    id == SPECIFIC_PURPOSE_REGION_ID || !size)
			continue;

		if (check_add_overflow(start, size, &end))
			continue;

		if (end <= vram_base || start >= vram_end)
			continue;

		resv_start = min(resv_start, max(start, vram_base));
		resv_end = max(resv_end, min(end, vram_end));
	}

	if (resv_start >= resv_end) {
		dev_warn(adev->dev,
			 "no MEM_RESERVED_INFO region inside VRAM [0x%llx, 0x%llx)\n",
			 vram_base, vram_end);
		return;
	}

	*offset = resv_start - vram_base;
	*reserve_size = resv_end - resv_start;
}

static const struct amdgpu_asic_funcs soc_v2_0_asic_funcs = {
	.read_bios_from_rom = &amdgpu_soc15_read_bios_from_rom,
	.read_register = &soc_v2_0_read_register,
	.reset = &soc_v2_0_asic_reset,
	.reset_method = &soc_v2_0_asic_reset_method,
	.get_xclk = &soc_v2_0_get_xclk,
	.get_config_memsize = &soc_v2_0_get_config_memsize,
	.init_doorbell_index = &soc_v2_0_init_doorbell_index,
	.need_reset_on_init = &soc_v2_0_need_reset_on_init,
	.supports_baco = &amdgpu_dpm_is_baco_supported,
	.update_umd_stable_pstate = &soc_v2_0_update_umd_stable_pstate,
	.get_fw_reserved_info = &soc_v2_0_get_fw_reserved_info,
};

static int soc_v2_0_common_early_init(struct amdgpu_ip_block *ip_block)
{
	struct amdgpu_device *adev = ip_block->adev;

	adev->nbio.funcs->set_reg_remap(adev);
	adev->reg.pcie.rreg = &amdgpu_device_indirect_rreg;
	adev->reg.pcie.wreg = &amdgpu_device_indirect_wreg;
	adev->reg.pcie.rreg_ext = &amdgpu_device_indirect_rreg_ext;
	adev->reg.pcie.wreg_ext = &amdgpu_device_indirect_wreg_ext;
	adev->reg.pcie.rreg64 = &amdgpu_device_indirect_rreg64;
	adev->reg.pcie.wreg64 = &amdgpu_device_indirect_wreg64;
	adev->reg.pcie.port_rreg = &amdgpu_device_pcie_port_rreg;
	adev->reg.pcie.port_wreg = &amdgpu_device_pcie_port_wreg;

	adev->asic_funcs = &soc_v2_0_asic_funcs;

	adev->rev_id = amdgpu_device_get_rev_id(adev);
	adev->external_rev_id = 0xff;

	switch (amdgpu_ip_version(adev, GC_HWIP, 0)) {
	case IP_VERSION(13, 0, 1):
		adev->cg_flags = 0;
		adev->pg_flags = 0;
		adev->external_rev_id = adev->rev_id + 0x10;
		break;
	default:
		return -EINVAL;
	}

	if (amdgpu_sriov_vf(adev)) {
		amdgpu_virt_init_setting(adev);
		xgpu_nv_mailbox_set_irq_funcs(adev);
	}

	return 0;
}

static int soc_v2_0_common_late_init(struct amdgpu_ip_block *ip_block)
{
	struct amdgpu_device *adev = ip_block->adev;

	if (amdgpu_sriov_vf(adev)) {
		xgpu_nv_mailbox_get_irq(adev);
	} else {
		if (adev->nbio.ras &&
		    adev->nbio.ras_err_event_athub_irq.funcs)
			/* don't need to fail gpu late init
			 * if enabling athub_err_event interrupt failed
			 * nbif v6_3_1 only support fatal error hanlding
			 * just enable the interrupt directly
			 */
			amdgpu_irq_get(adev, &adev->nbio.ras_err_event_athub_irq, 0);
	}

	/* Enable selfring doorbell aperture late because doorbell BAR
	 * aperture will change if resize BAR successfully in gmc sw_init.
	 */
	adev->nbio.funcs->enable_doorbell_selfring_aperture(adev, true);

	return 0;
}

static int soc_v2_0_common_sw_init(struct amdgpu_ip_block *ip_block)
{
	struct amdgpu_device *adev = ip_block->adev;

	if (amdgpu_sriov_vf(adev))
		xgpu_nv_mailbox_add_irq_id(adev);

	return 0;
}

static int soc_v2_0_common_hw_init(struct amdgpu_ip_block *ip_block)
{
	struct amdgpu_device *adev = ip_block->adev;

	/* setup nbio registers */
	if (adev->nbio.funcs &&
	    adev->nbio.funcs->init_registers)
		adev->nbio.funcs->init_registers(adev);
	/* remap HDP registers to a hole in mmio space,
	 * for the purpose of expose those registers
	 * to process space
	 */
	if (adev->nbio.funcs &&
	    adev->nbio.funcs->remap_hdp_registers)
		adev->nbio.funcs->remap_hdp_registers(adev);

	if (adev->df.funcs &&
	    adev->df.funcs->hw_init)
		adev->df.funcs->hw_init(adev);

	/* enable the doorbell aperture */
	if (adev->nbio.funcs &&
	    adev->nbio.funcs->enable_doorbell_aperture)
		adev->nbio.funcs->enable_doorbell_aperture(adev, true);

	return 0;
}

static int soc_v2_0_common_hw_fini(struct amdgpu_ip_block *ip_block)
{
	struct amdgpu_device *adev = ip_block->adev;

	/* Disable the doorbell aperture and selfring doorbell aperture
	 * separately in hw_fini because soc21_enable_doorbell_aperture
	 * has been removed and there is no need to delay disabling
	 * selfring doorbell.
	 */
	if (adev->nbio.funcs &&
	    adev->nbio.funcs->enable_doorbell_aperture)
		adev->nbio.funcs->enable_doorbell_aperture(adev, false);
	if (adev->nbio.funcs &&
	    adev->nbio.funcs->enable_doorbell_selfring_aperture)
		adev->nbio.funcs->enable_doorbell_selfring_aperture(adev, false);

	if (amdgpu_sriov_vf(adev)) {
		xgpu_nv_mailbox_put_irq(adev);
	} else {
		if (adev->nbio.ras &&
		    adev->nbio.ras_err_event_athub_irq.funcs)
			amdgpu_irq_put(adev, &adev->nbio.ras_err_event_athub_irq, 0);
	}

	return 0;
}

static int soc_v2_0_common_suspend(struct amdgpu_ip_block *ip_block)
{
	return soc_v2_0_common_hw_fini(ip_block);
}

static int soc_v2_0_common_resume(struct amdgpu_ip_block *ip_block)
{
	return soc_v2_0_common_hw_init(ip_block);
}

static int soc_v2_0_common_set_clockgating_state(struct amdgpu_ip_block *ip_block,
						 enum amd_clockgating_state state)
{
	struct amdgpu_device *adev = ip_block->adev;

	switch (amdgpu_ip_version(adev, NBIO_HWIP, 0)) {
	case IP_VERSION(7, 10, 0):
		if (adev->nbio.funcs &&
		    adev->nbio.funcs->update_medium_grain_clock_gating)
			adev->nbio.funcs->update_medium_grain_clock_gating(adev,
							state == AMD_CG_STATE_GATE);
		if (adev->nbio.funcs &&
		    adev->nbio.funcs->update_medium_grain_light_sleep)
			adev->nbio.funcs->update_medium_grain_light_sleep(adev,
							state == AMD_CG_STATE_GATE);
		if (adev->hdp.funcs &&
		    adev->hdp.funcs->update_clock_gating)
			adev->hdp.funcs->update_clock_gating(adev,
							state == AMD_CG_STATE_GATE);
		break;
	default:
		break;
	}
	return 0;
}

static int soc_v2_0_common_set_powergating_state(struct amdgpu_ip_block *ip_block,
					      enum amd_powergating_state state)
{
	struct amdgpu_device *adev = ip_block->adev;

	switch (amdgpu_ip_version(adev, LSDMA_HWIP, 0)) {
	case IP_VERSION(8, 0, 1):
		if (adev->lsdma.funcs &&
		    adev->lsdma.funcs->update_memory_power_gating)
			adev->lsdma.funcs->update_memory_power_gating(adev,
							state == AMD_PG_STATE_GATE);
		break;
	default:
		break;
	}

	return 0;
}

static void soc_v2_0_common_get_clockgating_state(struct amdgpu_ip_block *ip_block, u64 *flags)
{
	struct amdgpu_device *adev = ip_block->adev;

	if (adev->nbio.funcs &&
	    adev->nbio.funcs->get_clockgating_state)
		adev->nbio.funcs->get_clockgating_state(adev, flags);

	if (adev->hdp.funcs &&
	    adev->hdp.funcs->get_clock_gating_state)
		adev->hdp.funcs->get_clock_gating_state(adev, flags);

	return;
}

static const struct amd_ip_funcs soc_v2_0_common_ip_funcs = {
	.name = "soc_v2_0_common",
	.early_init = soc_v2_0_common_early_init,
	.late_init = soc_v2_0_common_late_init,
	.sw_init = soc_v2_0_common_sw_init,
	.hw_init = soc_v2_0_common_hw_init,
	.hw_fini = soc_v2_0_common_hw_fini,
	.suspend = soc_v2_0_common_suspend,
	.resume = soc_v2_0_common_resume,
	.set_clockgating_state = soc_v2_0_common_set_clockgating_state,
	.set_powergating_state = soc_v2_0_common_set_powergating_state,
	.get_clockgating_state = soc_v2_0_common_get_clockgating_state,
};
