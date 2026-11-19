// SPDX-License-Identifier: MIT
/*
 * Copyright © 2022 Intel Corporation
 */

#include "xe_uc.h"

#include "regs/xe_guc_regs.h"
#include "xe_assert.h"
#include "xe_device.h"
#include "xe_force_wake.h"
#include "xe_gsc.h"
#include "xe_gt.h"
#include "xe_gt_printk.h"
#include "xe_gt_sriov_vf.h"
#include "xe_guc.h"
#include "xe_guc_ct.h"
#include "xe_guc_pc.h"
#include "xe_guc_rc.h"
#include "xe_guc_engine_activity.h"
#include "xe_guc_submit.h"
#include "xe_huc.h"
#include "xe_mmio.h"
#include "xe_sriov.h"
#include "xe_tile.h"
#include "xe_uc_fw.h"
#include "xe_wedge.h"

static struct xe_gt *
uc_to_gt(struct xe_uc *uc)
{
	return container_of(uc, struct xe_gt, uc);
}

static struct xe_device *
uc_to_xe(struct xe_uc *uc)
{
	return gt_to_xe(uc_to_gt(uc));
}

/* Should be called once at driver load only */
int xe_uc_init_noalloc(struct xe_uc *uc)
{
	int ret;

	ret = xe_guc_init_noalloc(&uc->guc);
	if (ret)
		goto err;

	/* HuC and GSC have no early dependencies and will be initialized during xe_uc_init(). */
	return 0;

err:
	xe_gt_err(uc_to_gt(uc), "Failed to early initialize uC (%pe)\n", ERR_PTR(ret));
	return ret;
}

static bool __wopcm_regs_locked(struct xe_gt *gt,
				u32 *guc_wopcm_base, u32 *guc_wopcm_size)
{
	u32 reg_base = xe_mmio_read32(&gt->mmio, DMA_GUC_WOPCM_OFFSET);
	u32 reg_size = xe_mmio_read32(&gt->mmio, GUC_WOPCM_SIZE);

	if (!(reg_size & GUC_WOPCM_SIZE_LOCKED) ||
	    !(reg_base & GUC_WOPCM_OFFSET_VALID))
		return false;

	*guc_wopcm_base = reg_base & GUC_WOPCM_OFFSET_MASK;
	*guc_wopcm_size = reg_size & GUC_WOPCM_SIZE_MASK;
	return true;
}

static int __wopcm_init_regs(struct xe_gt *gt, u32 base, u32 size)
{
	u32 huc_agent = xe_uc_fw_is_available(&gt->uc.huc.fw) ? HUC_LOADING_AGENT_GUC : 0;
	u32 mask;
	int err;

	xe_gt_assert(gt, !(base & ~GUC_WOPCM_OFFSET_MASK));
	xe_gt_assert(gt, !(size & ~GUC_WOPCM_SIZE_MASK));

	mask = GUC_WOPCM_SIZE_MASK | GUC_WOPCM_SIZE_LOCKED;
	err = xe_mmio_write32_and_verify(&gt->mmio, GUC_WOPCM_SIZE, size, mask,
					 size | GUC_WOPCM_SIZE_LOCKED);
	if (err)
		goto err_out;

	mask = GUC_WOPCM_OFFSET_MASK | GUC_WOPCM_OFFSET_VALID | huc_agent;
	err = xe_mmio_write32_and_verify(&gt->mmio, DMA_GUC_WOPCM_OFFSET,
					 base | huc_agent, mask,
					 base | huc_agent |
					 GUC_WOPCM_OFFSET_VALID);
	if (err)
		goto err_out;

	xe_gt_dbg(gt, "Programmed GuC WOPCM [b=%uK, s=%uK]\n", base / SZ_1K, size / SZ_1K);

	return 0;

err_out:
	xe_gt_notice(gt, "Failed to init uC WOPCM registers to [b=%uK, s=%uK]!\n",
		     base / SZ_1K, size / SZ_1K);
	xe_gt_notice(gt, "%s(%#x)=%#x\n", "DMA_GUC_WOPCM_OFFSET",
		     DMA_GUC_WOPCM_OFFSET.addr,
		     xe_mmio_read32(&gt->mmio, DMA_GUC_WOPCM_OFFSET));
	xe_gt_notice(gt, "%s(%#x)=%#x\n", "GUC_WOPCM_SIZE",
		     GUC_WOPCM_SIZE.addr,
		     xe_mmio_read32(&gt->mmio, GUC_WOPCM_SIZE));

	return err;
}

static int uc_program_wopcm(struct xe_uc *uc)
{
	struct xe_gt *gt = uc_to_gt(uc);
	struct xe_tile *tile = gt_to_tile(gt);
	u32 huc_fw_size = xe_uc_fw_get_upload_size(&gt->uc.huc.fw);
	u32 wopcm_size = xe_tile_wopcm_size(tile);
	u32 guc_wopcm_base;
	u32 guc_wopcm_size;
	bool locked;

	if (!xe_uc_fw_is_supported(&gt->uc.guc.fw))
		return -ENODEV;

	xe_force_wake_assert_held(gt_to_fw(gt), XE_FW_GT);

	locked = __wopcm_regs_locked(gt, &guc_wopcm_base, &guc_wopcm_size);
	if (locked) {
		/*
		 * We trust the programming to have been done correctly. If
		 * something is wrong we'll catch it at FW load time.
		 */
		xe_gt_dbg(gt, "GuC WOPCM is already locked [b=%uK, s=%uK]\n",
			  guc_wopcm_base / SZ_1K, guc_wopcm_size / SZ_1K);
		return 0;
	}

	/*
	 * WOPCM partitioning on platforms with a media GT is more complex,
	 * because both GTs share the same WOPCM space. However, on all
	 * platforms with media GT we expect the registers to be preprogrammed
	 * by BIOS/IFWI, so we should never have to do the programming ourselves
	 * and can therefore skip the implementation.
	 */
	if (XE_WARN_ON(tile->media_gt)) {
		xe_gt_err(gt, "WOPCM not locked on platform with media GT\n");
		return -EIO;
	}

	/*
	 * On legacy HW (pre-PVC) where the driver is responsible for
	 * programming the WOPCM registers, the WOPCM is divided into three
	 * regions, in order from bottom to top:
	 * 1 - The HuC region, which contains the HuC firmware + a 16KB reserved
	 *     section.
	 * 2 - The GuC region, which contains the GuC firmware + a reserved
	 *     section for GuC's usage.
	 * 3 - A reserved region for HW contexts, which is 36KB in size.
	 *
	 * To keep the math simple, we remove the HW context region from the
	 * WOPCM size, calculate the size of region 1 and then leave the
	 * remaining area for region 2. The official binaries are guaranteed to
	 * fit in the WOPCM, so the math below can only go wrong if a user is
	 * manipulating the blobs. In such a scenario, we'll catch the error at
	 * FW load time, so no need to double verify it here.
	 */
	wopcm_size -= (SZ_32K + SZ_4K);

	guc_wopcm_base = huc_fw_size + SZ_16K;
	guc_wopcm_base = ALIGN(guc_wopcm_base, 1UL << GUC_WOPCM_OFFSET_SHIFT);

	guc_wopcm_size = wopcm_size - guc_wopcm_base; /* already 4KB aligned */

	return __wopcm_init_regs(gt, guc_wopcm_base, guc_wopcm_size);
}

int xe_uc_init(struct xe_uc *uc)
{
	int ret;

	/*
	 * We call the GuC/HuC/GSC init functions even if GuC submission is off
	 * to correctly move our tracking of the FW state to "disabled".
	 */
	ret = xe_guc_init(&uc->guc);
	if (ret)
		goto err;

	ret = xe_huc_init(&uc->huc);
	if (ret)
		goto err;

	ret = xe_gsc_init(&uc->gsc);
	if (ret)
		goto err;

	if (!xe_device_uc_enabled(uc_to_xe(uc)))
		return 0;

	if (!IS_SRIOV_VF(uc_to_xe(uc))) {
		ret = uc_program_wopcm(uc);
		if (ret)
			goto err;
	}

	ret = xe_guc_min_load_for_hwconfig(&uc->guc);
	if (ret)
		goto err;

	return 0;
err:
	xe_gt_err(uc_to_gt(uc), "Failed to initialize uC (%pe)\n", ERR_PTR(ret));
	return ret;
}

/**
 * xe_uc_init_post_hwconfig - init Uc post hwconfig load
 * @uc: The UC object
 *
 * Return: 0 on success, negative error code on error.
 */
int xe_uc_init_post_hwconfig(struct xe_uc *uc)
{
	int err;

	/* GuC submission not enabled, nothing to do */
	if (!xe_device_uc_enabled(uc_to_xe(uc)))
		return 0;

	err = xe_uc_sanitize_reset(uc);
	if (err)
		return err;

	err = xe_guc_init_post_hwconfig(&uc->guc);
	if (err)
		return err;

	err = xe_huc_init_post_hwconfig(&uc->huc);
	if (err)
		return err;

	return xe_gsc_init_post_hwconfig(&uc->gsc);
}

static int uc_reset(struct xe_uc *uc)
{
	struct xe_device *xe = uc_to_xe(uc);
	int ret;

	ret = xe_guc_reset(&uc->guc);
	if (ret) {
		drm_err(&xe->drm, "Failed to reset GuC, ret = %d\n", ret);
		return ret;
	}

	return 0;
}

static void xe_uc_sanitize(struct xe_uc *uc)
{
	xe_huc_sanitize(&uc->huc);
	xe_guc_sanitize(&uc->guc);
}

int xe_uc_sanitize_reset(struct xe_uc *uc)
{
	xe_uc_sanitize(uc);

	return uc_reset(uc);
}

static int vf_uc_load_hw(struct xe_uc *uc)
{
	int err;

	err = xe_uc_sanitize_reset(uc);
	if (err)
		return err;

	err = xe_guc_enable_communication(&uc->guc);
	if (err)
		return err;

	err = xe_gt_sriov_vf_connect(uc_to_gt(uc));
	if (err)
		return err;

	err = xe_guc_opt_in_features_enable(&uc->guc);
	if (err)
		return err;

	err = xe_guc_submit_enable(&uc->guc);
	if (err)
		return err;

	err = xe_gt_record_default_lrcs(uc_to_gt(uc));
	if (err)
		return err;

	return 0;
}

/*
 * Should be called during driver load, after every GT reset, and after every
 * suspend to reload / auth the firmwares.
 */
int xe_uc_load_hw(struct xe_uc *uc)
{
	int ret;

	/* GuC submission not enabled, nothing to do */
	if (!xe_device_uc_enabled(uc_to_xe(uc)))
		return 0;

	if (IS_SRIOV_VF(uc_to_xe(uc)))
		return vf_uc_load_hw(uc);

	ret = uc_program_wopcm(uc);
	if (ret)
		return ret;

	ret = xe_huc_upload(&uc->huc);
	if (ret)
		return ret;

	ret = xe_guc_upload(&uc->guc);
	if (ret)
		return ret;

	ret = xe_guc_enable_communication(&uc->guc);
	if (ret)
		return ret;

	ret = xe_gt_record_default_lrcs(uc_to_gt(uc));
	if (ret)
		return ret;

	ret = xe_guc_post_load_init(&uc->guc);
	if (ret)
		return ret;

	ret = xe_guc_pc_start(&uc->guc.pc);
	if (ret)
		return ret;

	ret = xe_guc_rc_enable(&uc->guc);
	if (ret)
		return ret;

	xe_guc_engine_activity_enable_stats(&uc->guc);

	/* We don't fail the driver load if HuC fails to auth */
	ret = xe_huc_auth(&uc->huc, XE_HUC_AUTH_VIA_GUC);
	if (ret)
		xe_gt_err(uc_to_gt(uc),
			  "HuC authentication failed (%pe), continuing with no HuC\n",
			  ERR_PTR(ret));

	/* GSC load is async */
	xe_gsc_load_start(&uc->gsc);

	return 0;
}

int xe_uc_reset_prepare(struct xe_uc *uc)
{
	/* GuC submission not enabled, nothing to do */
	if (!xe_device_uc_enabled(uc_to_xe(uc)))
		return 0;

	return xe_guc_reset_prepare(&uc->guc);
}

void xe_uc_stop_prepare(struct xe_uc *uc)
{
	xe_gsc_stop_prepare(&uc->gsc);
	xe_guc_stop_prepare(&uc->guc);
}

void xe_uc_stop(struct xe_uc *uc)
{
	/* GuC submission not enabled, nothing to do */
	if (!xe_device_uc_enabled(uc_to_xe(uc)))
		return;

	xe_guc_stop(&uc->guc);
}

int xe_uc_start(struct xe_uc *uc)
{
	/* GuC submission not enabled, nothing to do */
	if (!xe_device_uc_enabled(uc_to_xe(uc)))
		return 0;

	return xe_guc_start(&uc->guc);
}

static void uc_reset_wait(struct xe_uc *uc)
{
	int ret;

again:
	xe_guc_reset_wait(&uc->guc);

	ret = xe_uc_reset_prepare(uc);
	if (ret)
		goto again;
}

static void uc_flr_prepare(struct work_struct *w)
{
	struct xe_uc_flr *flr = container_of(w, struct xe_uc_flr, work);
	struct xe_uc *uc = flr->uc;

	xe_gt_assert(uc_to_gt(uc), xe_wedged(uc_to_xe(uc)));

	xe_uc_reset_prepare(uc);
	xe_uc_stop(uc);
	xe_guc_flr_prepare(&uc->guc);
}

static void uc_flr_sanitize(struct work_struct *w)
{
	struct xe_uc_flr *flr = container_of(w, struct xe_uc_flr, work);
	struct xe_uc *uc = flr->uc;

	/* TODO: Sanitize GSC firmware */
	xe_gt_assert(uc_to_gt(uc), IS_DGFX(uc_to_xe(uc)));
	xe_gt_assert(uc_to_gt(uc), !xe_uc_fw_is_loadable(&uc->gsc.fw));

	xe_guc_submit_stop(&uc->guc);
	xe_uc_sanitize(uc);
}

/**
 * xe_uc_flr_prepare() - Prepare uCs for FLR
 * @uc: The uC object
 *
 * Tear down pending work and stop all uCs.
 */
void xe_uc_flr_prepare(struct xe_uc *uc)
{
	struct xe_uc_flr flr = { .uc = uc };
	struct xe_gt *gt = uc_to_gt(uc);

	xe_uc_reset_prepare(uc);

	/*
	 * We'll be tearing down exec queues which signals the fences and frees the
	 * jobs but all of that happens asynchronously, so make sure we don't disrupt
	 * the scheduler while jobs are still in-flight.
	 */
	INIT_WORK_ONSTACK(&flr.work, uc_flr_prepare);
	queue_work(gt->ordered_wq, &flr.work);
	flush_work(&flr.work);
	destroy_work_on_stack(&flr.work);

	INIT_WORK_ONSTACK(&flr.work, uc_flr_sanitize);
	queue_work(gt->ordered_wq, &flr.work);
	flush_work(&flr.work);
	destroy_work_on_stack(&flr.work);
}

/**
 * xe_uc_reinit() - Re-initialize uCs after FLR
 * @uc: The uC object
 *
 * Returns: 0 on success, negative error code otherwise.
 */
int xe_uc_reinit(struct xe_uc *uc)
{
	int ret;

	ret = xe_guc_reinit(&uc->guc);
	if (ret)
		return ret;

	ret = xe_huc_reinit(&uc->huc);
	if (ret)
		return ret;

	return xe_gsc_reinit(&uc->gsc);
}

void xe_uc_suspend_prepare(struct xe_uc *uc)
{
	xe_gsc_wait_for_worker_completion(&uc->gsc);
	xe_guc_stop_prepare(&uc->guc);
}

int xe_uc_suspend(struct xe_uc *uc)
{
	/* GuC submission not enabled, nothing to do */
	if (!xe_device_uc_enabled(uc_to_xe(uc)))
		return 0;

	uc_reset_wait(uc);

	xe_uc_stop(uc);

	return xe_guc_suspend(&uc->guc);
}

/**
 * xe_uc_resume_early() - Early init for UC resume
 * @uc: the UC object
 *
 * UC init before a GT restart during resume.
 */
void xe_uc_resume_early(struct xe_uc *uc)
{
	if (!xe_device_uc_enabled(uc_to_xe(uc)))
		return;

	xe_guc_resume_early(&uc->guc);
}

/**
 * xe_uc_runtime_suspend() - UC runtime suspend
 * @uc: the UC object
 *
 * Runtime suspend all UCs.
 */
void xe_uc_runtime_suspend(struct xe_uc *uc)
{
	if (!xe_device_uc_enabled(uc_to_xe(uc)))
		return;

	xe_guc_runtime_suspend(&uc->guc);
}

/**
 * xe_uc_runtime_resume() - UC runtime resume
 * @uc: the UC object
 *
 * Runtime resume all UCs.
 */
void xe_uc_runtime_resume(struct xe_uc *uc)
{
	if (!xe_device_uc_enabled(uc_to_xe(uc)))
		return;

	xe_guc_runtime_resume(&uc->guc);
}

/**
 * xe_uc_wedge_declare() - Declare UC wedged
 * @uc: the UC object
 *
 * Wedge the UC which stops all submission, saves desired debug state, and
 * cleans up anything which could timeout.
 */
void xe_uc_wedge_declare(struct xe_uc *uc)
{
	xe_gt_assert(uc_to_gt(uc), uc_to_xe(uc)->wedged.mode);

	xe_guc_wedge_declare(&uc->guc);
}
