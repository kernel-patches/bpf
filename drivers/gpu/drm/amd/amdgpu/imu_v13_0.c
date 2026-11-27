/*
 * Copyright 2025 Advanced Micro Devices, Inc.
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
#include "amdgpu.h"
#include "amdgpu_imu.h"
#include "amdgpu_dpm.h"

#include "imu_v13_0.h"

#include "gc/gc_13_0_1_offset.h"
#include "gc/gc_13_0_1_sh_mask.h"
#include "mmhub/mmhub_5_0_1_offset.h"

MODULE_FIRMWARE("amdgpu/gc_13_0_1_imu.bin");

#define TRANSFER_RAM_MASK	0x001c0000

static int imu_v13_0_init_microcode(struct amdgpu_device *adev)
{
	char ucode_prefix[15];
	int err;
	const struct imu_firmware_header_v1_0 *imu_hdr;
	struct amdgpu_firmware_info *info = NULL;

	DRM_DEBUG("\n");

	amdgpu_ucode_ip_version_decode(adev, GC_HWIP, ucode_prefix, sizeof(ucode_prefix));
	err = amdgpu_ucode_request(adev, &adev->gfx.imu_fw, AMDGPU_UCODE_REQUIRED,
				   "amdgpu/%s_imu.bin", ucode_prefix);
	if (err)
		goto out;

	imu_hdr = (const struct imu_firmware_header_v1_0 *)adev->gfx.imu_fw->data;
	adev->gfx.imu_fw_version = le32_to_cpu(imu_hdr->header.ucode_version);

	if (adev->firmware.load_type == AMDGPU_FW_LOAD_PSP) {
		info = &adev->firmware.ucode[AMDGPU_UCODE_ID_IMU_I];
		info->ucode_id = AMDGPU_UCODE_ID_IMU_I;
		info->fw = adev->gfx.imu_fw;
		adev->firmware.fw_size +=
			ALIGN(le32_to_cpu(imu_hdr->imu_iram_ucode_size_bytes), PAGE_SIZE);
		info = &adev->firmware.ucode[AMDGPU_UCODE_ID_IMU_D];
		info->ucode_id = AMDGPU_UCODE_ID_IMU_D;
		info->fw = adev->gfx.imu_fw;
		adev->firmware.fw_size +=
			ALIGN(le32_to_cpu(imu_hdr->imu_dram_ucode_size_bytes), PAGE_SIZE);
	}

out:
	if (err) {
		dev_err(adev->dev,
			"gfx13: Failed to load firmware \"%s_imu.bin\"\n",
			ucode_prefix);
		amdgpu_ucode_release(&adev->gfx.imu_fw);
	}

	return err;
}

static int imu_v13_0_load_microcode(struct amdgpu_device *adev)
{
	const struct imu_firmware_header_v1_0 *hdr;
	const __le32 *fw_data;
	unsigned i, fw_size;

	if (!adev->gfx.imu_fw)
		return -EINVAL;

	hdr = (const struct imu_firmware_header_v1_0 *)adev->gfx.imu_fw->data;

	fw_data = (const __le32 *)(adev->gfx.imu_fw->data +
			le32_to_cpu(hdr->header.ucode_array_offset_bytes));
	fw_size = le32_to_cpu(hdr->imu_iram_ucode_size_bytes) / 4;

	WREG32_SOC15(GC, 0, regGFX_IMU_I_RAM_ADDR, 0);

	for (i = 0; i < fw_size; i++)
		WREG32_SOC15(GC, 0, regGFX_IMU_I_RAM_DATA, le32_to_cpup(fw_data++));

	WREG32_SOC15(GC, 0, regGFX_IMU_I_RAM_ADDR, adev->gfx.imu_fw_version);

	fw_data = (const __le32 *)(adev->gfx.imu_fw->data +
			le32_to_cpu(hdr->header.ucode_array_offset_bytes) +
			le32_to_cpu(hdr->imu_iram_ucode_size_bytes));
	fw_size = le32_to_cpu(hdr->imu_dram_ucode_size_bytes) / 4;

	WREG32_SOC15(GC, 0, regGFX_IMU_D_RAM_ADDR, 0);

	for (i = 0; i < fw_size; i++)
		WREG32_SOC15(GC, 0, regGFX_IMU_D_RAM_DATA, le32_to_cpup(fw_data++));

	WREG32_SOC15(GC, 0, regGFX_IMU_D_RAM_ADDR, adev->gfx.imu_fw_version);

	return 0;
}

static int imu_v13_0_wait_for_reset_status(struct amdgpu_device *adev)
{
	u32 imu_reg_val = 0;
	int i;

	for (i = 0; i < adev->usec_timeout; i++) {
		imu_reg_val = RREG32_SOC15(GC, 0, regGFX_IMU_GFX_RESET_CTRL);
		if ((imu_reg_val & 0x1f) == 0x1f)
			break;
		udelay(1);
	}

	if (i >= adev->usec_timeout) {
		dev_err(adev->dev, "init imu: IMU start timeout\n");
		return -ETIMEDOUT;
	}

	return 0;
}

static void imu_v13_0_setup(struct amdgpu_device *adev)
{
	u32 imu_reg_val;

	WREG32_SOC15(GC, 0, regGFX_IMU_C2PMSG_ACCESS_CTRL0, 0xffffff);
	WREG32_SOC15(GC, 0, regGFX_IMU_C2PMSG_ACCESS_CTRL1, 0xffff);

	if (adev->gfx.imu.mode == DEBUG_MODE) {
		imu_reg_val = RREG32_SOC15(GC, 0, regGFX_IMU_C2PMSG_16);
		imu_reg_val |= 0x1;
		WREG32_SOC15(GC, 0, regGFX_IMU_C2PMSG_16, imu_reg_val);

		imu_reg_val = RREG32_SOC15(GC, 0, regGFX_IMU_SCRATCH_10);
		imu_reg_val |= 0x10007;
		WREG32_SOC15(GC, 0, regGFX_IMU_SCRATCH_10, imu_reg_val);

	}
}

static int imu_v13_0_start(struct amdgpu_device *adev)
{
	u32 imu_reg_val;

	imu_reg_val = RREG32_SOC15(GC, 0, regGFX_IMU_CORE_CTRL);
	imu_reg_val &= 0xfffffffe;
	WREG32_SOC15(GC, 0, regGFX_IMU_CORE_CTRL, imu_reg_val);

	if (adev->flags & AMD_IS_APU)
		amdgpu_dpm_set_gfx_power_up_by_imu(adev);

	return imu_v13_0_wait_for_reset_status(adev);
}

static u32 imu_v13_0_grbm_gfx_index_remap(struct amdgpu_device *adev,
					  u32 data, bool high)
{
	u32 val, inst_index;

	inst_index = REG_GET_FIELD(data, GRBM_GFX_INDEX, INSTANCE_INDEX);

	if (high)
		val = inst_index >> 5;
	else
		val = REG_GET_FIELD(data, GRBM_GFX_INDEX, SE_BROADCAST_WRITES) << 18 |
		      REG_GET_FIELD(data, GRBM_GFX_INDEX, SA_BROADCAST_WRITES) << 19 |
		      REG_GET_FIELD(data, GRBM_GFX_INDEX, INSTANCE_BROADCAST_WRITES) << 20 |
		      REG_GET_FIELD(data, GRBM_GFX_INDEX, SE_INDEX) << 21 |
		      REG_GET_FIELD(data, GRBM_GFX_INDEX, SA_INDEX) << 25 |
		      (inst_index & 0x1f);

	return val;
}

static u32 imu_v13_init_gfxhub_settings(struct amdgpu_device *adev,
					u32 reg, u32 data)
{
	if (reg == SOC15_REG_OFFSET(GC, 0, regGCMC_VM_FB_LOCATION_BASE))
		return RREG32_SOC15(MMHUB, 0, regMMMC_VM_FB_LOCATION_BASE);
	else if (reg == SOC15_REG_OFFSET(GC, 0, regGCMC_VM_FB_LOCATION_TOP))
		return RREG32_SOC15(MMHUB, 0, regMMMC_VM_FB_LOCATION_TOP);
	else if (reg == SOC15_REG_OFFSET(GC, 0, regGCMC_VM_FB_OFFSET))
		return RREG32_SOC15(MMHUB, 0, regMMMC_VM_FB_OFFSET);
	else if (reg == SOC15_REG_OFFSET(GC, 0, regGCMC_VM_AGP_BASE))
		return RREG32_SOC15(MMHUB, 0, regMMMC_VM_AGP_BASE);
	else if (reg == SOC15_REG_OFFSET(GC, 0, regGCMC_VM_AGP_BOT))
		return RREG32_SOC15(MMHUB, 0, regMMMC_VM_AGP_BOT);
	else if (reg == SOC15_REG_OFFSET(GC, 0, regGCMC_VM_AGP_TOP))
		return RREG32_SOC15(MMHUB, 0, regMMMC_VM_AGP_TOP);
	else if (reg == SOC15_REG_OFFSET(GC, 0, regGCMC_VM_MX_L1_TLB_CNTL))
		return RREG32_SOC15(MMHUB, 0, regMMMC_VM_MX_L1_TLB_CNTL);
	else if (reg == SOC15_REG_OFFSET(GC, 0, regGCMC_VM_SYSTEM_APERTURE_LOW_ADDR))
		return RREG32_SOC15(MMHUB, 0, regMMMC_VM_SYSTEM_APERTURE_LOW_ADDR);
	else if (reg == SOC15_REG_OFFSET(GC, 0, regGCMC_VM_SYSTEM_APERTURE_HIGH_ADDR))
		return RREG32_SOC15(MMHUB, 0, regMMMC_VM_SYSTEM_APERTURE_HIGH_ADDR);
	else if (reg == SOC15_REG_OFFSET(GC, 0, regGCMC_VM_LOCAL_FB_ADDRESS_START))
		return RREG32_SOC15(MMHUB, 0, regMMMC_VM_LOCAL_FB_ADDRESS_START);
	else if (reg == SOC15_REG_OFFSET(GC, 0, regGCMC_VM_LOCAL_FB_ADDRESS_END))
		return RREG32_SOC15(MMHUB, 0, regMMMC_VM_LOCAL_FB_ADDRESS_END);
	else if (reg == SOC15_REG_OFFSET(GC, 0, regGCMC_VM_LOCAL_SYSMEM_ADDRESS_START))
		return RREG32_SOC15(MMHUB, 0, regMMMC_VM_LOCAL_SYSMEM_ADDRESS_START);
	else if (reg == SOC15_REG_OFFSET(GC, 0, regGCMC_VM_LOCAL_SYSMEM_ADDRESS_END))
		return RREG32_SOC15(MMHUB, 0, regMMMC_VM_LOCAL_SYSMEM_ADDRESS_END);
	else if (reg == SOC15_REG_OFFSET(GC, 0, regGCMC_VM_SYSTEM_APERTURE_DEFAULT_ADDR_LSB))
		return RREG32_SOC15(MMHUB, 0, regMMMC_VM_SYSTEM_APERTURE_DEFAULT_ADDR_LSB);
	else if (reg == SOC15_REG_OFFSET(GC, 0, regGCMC_VM_SYSTEM_APERTURE_DEFAULT_ADDR_MSB))
		return RREG32_SOC15(MMHUB, 0, regMMMC_VM_SYSTEM_APERTURE_DEFAULT_ADDR_MSB);
	else
		return data;
}

static void program_imu_rlc_ram(struct amdgpu_device *adev,
				const u32 *regs,
				const u32 array_size)
{
	u32 reg, data, val_h = 0, val_l = TRANSFER_RAM_MASK;
	int i;

	if (array_size % 3)
		return;

	for (i = 0; i < array_size; i += 3) {
		reg = regs[i + 0];
		data = regs[i + 2];
		data = imu_v13_init_gfxhub_settings(adev, reg, data);
		if (reg == SOC15_REG_OFFSET(GC, 0, regGRBM_GFX_INDEX)) {
			val_l = imu_v13_0_grbm_gfx_index_remap(adev, data, false);
			val_h = imu_v13_0_grbm_gfx_index_remap(adev, data, true);
		} else {
			WREG32_SOC15(GC, 0, regGFX_IMU_RLC_RAM_ADDR_HIGH, val_h);
			WREG32_SOC15(GC, 0, regGFX_IMU_RLC_RAM_ADDR_LOW, reg | val_l);
			WREG32_SOC15(GC, 0, regGFX_IMU_RLC_RAM_DATA, data);
		}
	}
}

static void imu_v13_0_program_rlc_ram(struct amdgpu_device *adev)
{
	u32 reg_data, size = 0;
	const u32 *data;
	int r = -EINVAL;

	WREG32_SOC15(GC, 0, regGFX_IMU_RLC_RAM_INDEX, 0x2);

	switch (amdgpu_ip_version(adev, GC_HWIP, 0)) {
	case IP_VERSION(13, 0, 1):
		if (!r)
			program_imu_rlc_ram(adev, data, (const u32)size);
		break;
	default:
		BUG();
		break;
	}

	//Indicate the latest entry
	WREG32_SOC15(GC, 0, regGFX_IMU_RLC_RAM_ADDR_HIGH, 0);
	WREG32_SOC15(GC, 0, regGFX_IMU_RLC_RAM_ADDR_LOW, 0);
	WREG32_SOC15(GC, 0, regGFX_IMU_RLC_RAM_DATA, 0);

	reg_data = RREG32_SOC15(GC, 0, regGFX_IMU_RLC_RAM_INDEX);
	reg_data |= GFX_IMU_RLC_RAM_INDEX__RAM_VALID_MASK;
	WREG32_SOC15(GC, 0, regGFX_IMU_RLC_RAM_INDEX, reg_data);
}

const struct amdgpu_imu_funcs gfx_v13_0_imu_funcs = {
	.init_microcode = imu_v13_0_init_microcode,
	.load_microcode = imu_v13_0_load_microcode,
	.setup_imu = imu_v13_0_setup,
	.start_imu = imu_v13_0_start,
	.program_rlc_ram = imu_v13_0_program_rlc_ram,
	.wait_for_reset_status = imu_v13_0_wait_for_reset_status,
};
