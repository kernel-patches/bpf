// SPDX-License-Identifier: MIT
/*
 * Copyright © 2026 Intel Corporation
 */

#include <linux/pci.h>

#include <generated/xe_device_wa_oob.h>

#include "xe_device.h"
#include "xe_gt.h"
#include "xe_hw_error.h"
#include "xe_log.h"
#include "xe_pci.h"
#include "xe_pcode.h"
#include "xe_pm.h"
#include "xe_printk.h"
#include "xe_ras.h"
#include "xe_sriov_pf_helpers.h"
#include "xe_survivability_mode.h"
#include "xe_wa.h"
#include "xe_wedge.h"

/**
 * DOC: Xe PCI Error Handling
 *
 * Xe driver registers PCI callbacks which are called by PCI core in case of
 * bus errors or resets.
 *
 * Currently both Function Level Reset (FLR) and bus error handling callbacks are
 * supported. Both wipe the VRAM and resets the state of all the hardware units.
 * Therefore, the contents of all exec queues and BOs in VRAM are lost, and the
 * hardware needs a full re-initialization. The way Xe driver handles it, is
 * pretty much similar to system suspend/resume flow with a few notable exceptions.
 *
 * Prepare phase:
 *
 * - Temporarily wedge the device to prevent userspace access
 * - Kill exec queues which signals the fences and frees in-flight jobs
 * - Stop the scheduler and all submissions to GuC
 * - The fact that FLR is needed is because hardware could be in corrupted state
 *   and access unreliable, so skip memory eviction due to untrustworthy VRAM
 *   contents
 * - Remove all memory mappings since VRAM contents will be lost
 *
 * Re-initialization phase:
 *
 * - Recreate kernel BOs due to skipped memory eviction in prepare phase
 * - Restore kernel queues which were killed in prepare phase
 * - Reload all uC firmwares
 * - Bring up all hardware units
 * - Unwedge the device to allow userspace access
 *
 * Since VRAM contents are lost, the user is expected to recreate user memory
 * and reload context.
 *
 * TODO: Reuse FLR callbacks for bus error handling.
 *
 * Current implementation is only limited to re-initializing GT. This needs to
 * be extended for a lot of components listed below.
 *
 * - Proper re-initialization of GSC and PXP for integrated platforms
 * - SR-IOV cases which need PF and VF synchronization
 * - Re-initialization of all child devices registered by Xe
 * - MM corner cases
 * - Display
 */

static void prepare_device_for_reset(struct pci_dev *pdev)
{
	struct xe_device *xe = pdev_to_xe_device(pdev);
	struct xe_gt *gt;
	u8 id;

	/* Wedge the device to prevent userspace access but do not send the uevent. */
	xe_wedge_get(xe);

	xe_device_set_in_reset(xe);

	for_each_gt(gt, xe, id) {
		xe_gt_wedge_declare(gt);
		flush_work(&gt->wedge.worker);
	}

	pci_disable_device(pdev);
}

static pci_ers_result_t ras_action_to_pci_result(struct pci_dev *pdev, u8 action)
{
	struct xe_device *xe = xe_any_to_xe(pdev);

	switch (action) {
	case XE_RAS_RECOVERY_ACTION_RECOVERED:
		return PCI_ERS_RESULT_RECOVERED;
	case XE_RAS_RECOVERY_ACTION_RESET:
		/* We should not be doing such ugly hacks, reuse FLR callbacks and drop this. */
		if (atomic_xchg(&xe->wedged.perm, 1))
			return PCI_ERS_RESULT_DISCONNECT;

		prepare_device_for_reset(pdev);
		return PCI_ERS_RESULT_NEED_RESET;
	case XE_RAS_RECOVERY_ACTION_DISCONNECT:
		return PCI_ERS_RESULT_DISCONNECT;
	default:
		return PCI_ERS_RESULT_DISCONNECT;
	}
}

static bool is_aer_internal_error(struct pci_dev *pdev)
{
	struct pci_dev *usp;
	u16 aer_cap;
	u32 status;

	usp = xe_pci_get_usp_dev(pdev);
	if (!usp)
		return false;

	aer_cap = pci_find_ext_capability(usp, PCI_EXT_CAP_ID_ERR);
	if (!aer_cap) {
		dev_warn_once(&usp->dev, "AER capability unavailable\n");
		return false;
	}

	pci_read_config_dword(usp, aer_cap + PCI_ERR_UNCOR_STATUS, &status);
	if (PCI_POSSIBLE_ERROR(status))
		return false;

	return status & PCI_ERR_UNC_INTN;
}

static pci_ers_result_t xe_pci_error_detected(struct pci_dev *pdev, pci_channel_state_t state)
{
	struct xe_device *xe = pdev_to_xe_device(pdev);

	xe_info(xe, "PCI error: detected state = %d\n", state);

	if (state == pci_channel_io_perm_failure)
		return PCI_ERS_RESULT_DISCONNECT;

	/* If the device is already in survivability mode, do not attempt recovery */
	if (xe_survivability_mode_is_boot_enabled(xe))
		return PCI_ERS_RESULT_DISCONNECT;

	/*
	 * If non-fatal error processing is in progress when uncorrectable internal error occurs,
	 * flush and disable the worker to prevent further processing, as a reset is imminent.
	 */
	if (XE_DEVICE_WA(xe, 14028434957) && is_aer_internal_error(pdev)) {
		xe_ras_set_aer_internal_error(xe);
		xe_hw_error_work_disable(xe);
	}

	if (xe_wedged(xe))
		return PCI_ERS_RESULT_DISCONNECT;

	switch (state) {
	case pci_channel_io_normal:
		return PCI_ERS_RESULT_CAN_RECOVER;
	case pci_channel_io_frozen:
		/* We should not be doing such ugly hacks, reuse FLR callbacks and drop this. */
		if (atomic_xchg(&xe->wedged.perm, 1))
			return PCI_ERS_RESULT_DISCONNECT;

		prepare_device_for_reset(pdev);
		return PCI_ERS_RESULT_NEED_RESET;
	default:
		xe_info(xe, "PCI error: unknown state %d\n", state);
		return PCI_ERS_RESULT_DISCONNECT;
	}
}

static pci_ers_result_t xe_pci_error_mmio_enabled(struct pci_dev *pdev)
{
	struct xe_device *xe = pdev_to_xe_device(pdev);
	enum xe_ras_recovery_action action;

	xe_info(xe, "PCI error: MMIO enabled\n");
	action = xe_ras_process_errors(xe);

	/* User wants to debug the error, prevent reset */
	if (xe->wedged.mode == XE_WEDGED_MODE_UPON_ANY_HANG_NO_RESET) {
		xe_wedge_declare(xe, DRM_WEDGE_RECOVERY_NONE);
		return PCI_ERS_RESULT_DISCONNECT;
	}

	return ras_action_to_pci_result(pdev, action);
}

static pci_ers_result_t xe_pci_error_slot_reset(struct pci_dev *pdev)
{
	const struct pci_device_id *ent = pci_match_id(pdev->driver->id_table, pdev);
	struct xe_device *xe = pdev_to_xe_device(pdev);
	int err;

	xe_info(xe, "PCI error: slot reset\n");

	pci_restore_state(pdev);

	err = pci_enable_device(pdev);
	if (err) {
		xe_log_err_fatal(xe, PCI, err, "Cannot re-enable PCI device after reset\n");
		return PCI_ERS_RESULT_DISCONNECT;
	}

	err = xe_pcode_ready(xe, true);
	/* TODO: dump survivability info on pcode init failure */
	if (err)
		return PCI_ERS_RESULT_DISCONNECT;

	/*
	 * Secondary Bus Reset causes all VRAM state to be lost along with
	 * hardware state. As an initial step, re-probe the device to
	 * re-initialize the driver and hardware.
	 * TODO: optimize by re-initializing only the hardware state and re-creating
	 * kernel BOs.
	 */
	xe_device_clear_in_reset(xe);
	pdev->driver->remove(pdev);
	devres_release_group(&pdev->dev, xe->devres_group);

	if (pdev->driver->probe(pdev, ent))
		return PCI_ERS_RESULT_DISCONNECT;

	return PCI_ERS_RESULT_RECOVERED;
}

static void xe_pci_error_resume(struct pci_dev *pdev)
{
	struct xe_device *xe = pdev_to_xe_device(pdev);

	xe_info(xe, "PCI error: resume\n");
}

static inline bool xe_pci_reset_skip(struct xe_device *xe)
{
	return !IS_DGFX(xe) || IS_SRIOV_VF(xe) || xe_sriov_pf_num_vfs(xe) || xe->info.probe_display;
}

static void xe_pci_reset_prepare(struct pci_dev *pdev)
{
	struct xe_device *xe = pdev_to_xe_device(pdev);
	int err;

	err = xe_survivability_mode_is_boot_enabled(xe);
	if (err) {
		xe_err(xe, "PCI reset: device in survivability mode\n");
		return;
	}

	err = xe_wedged(xe);
	if (err)
		xe_err(xe, "PCI reset: device in unexpected state\n");

	/* Wedge the device to prevent userspace access but don't send the event yet */
	xe_wedge_get(xe);
	if (err)
		return;

	err = xe_pci_reset_skip(xe);
	if (err) {
		xe_err(xe, "PCI reset: not supported\n");
		return;
	}

	/*
	 * The hardware could be in corrupted state and access unreliable, but we try to
	 * update data structures and cleanup any pending work to avoid side effects during
	 * PCIe FLR. This will be similar to system suspend flow but without eviction.
	 */
	err = xe_device_suspend(xe, false, true);
	if (err) {
		xe_err(xe, "PCI reset: failed to prepare\n");
		return;
	}

	xe->flr_prepared = true;
	xe_info(xe, "PCI reset: prepared\n");
}

static void xe_pci_reset_done(struct pci_dev *pdev)
{
	struct xe_device *xe = pdev_to_xe_device(pdev);
	int err;

	err = xe_survivability_mode_is_boot_enabled(xe);
	if (err)
		return;

	if (!xe->flr_prepared)
		goto out;

	/* Unprepare early in case we fail */
	xe->flr_prepared = false;

	/*
	 * We already have the data structures intact, so try to re-initialize the device.
	 * This will be similar to system resume flow, except we'll also need to recreate
	 * kernel bos and restore kernel queues.
	 */
	err = xe_device_resume(xe, true);
	if (err) {
		xe_err(xe, "PCI reset: re-initialization failed\n");
		goto out;
	}

	/* Unwedge to allow userspace access */
	xe_wedge_put(xe);
	xe_info(xe, "PCI reset: done\n");

	return;
out:
	/* Most likely the device is unusable and there's nothing we can do about it */
	xe_wedge_declare(xe, DRM_WEDGE_RECOVERY_REBIND | DRM_WEDGE_RECOVERY_BUS_RESET);
	/* Drop local reference */
	xe_wedge_put(xe);
}

const struct pci_error_handlers xe_pci_error_handlers = {
	.error_detected	= xe_pci_error_detected,
	.mmio_enabled	= xe_pci_error_mmio_enabled,
	.slot_reset	= xe_pci_error_slot_reset,
	.resume		= xe_pci_error_resume,
	.reset_prepare	= xe_pci_reset_prepare,
	.reset_done	= xe_pci_reset_done,
};
