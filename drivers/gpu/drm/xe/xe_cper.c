// SPDX-License-Identifier: MIT
/*
 * Copyright © 2026 Intel Corporation
 */

#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/minmax.h>
#include <linux/pci.h>

#include "xe_cper.h"
#include "xe_cper_types.h"
#include "xe_device.h"
#include "xe_printk.h"
#include "xe_ras.h"
#include "xe_ras_types.h"

static bool is_sigid(u32 sigid)
{
	return sigid != INTEL_SIGID_INVALID && sigid != U32_MAX;
}

static bool is_hw_sigid(enum xe_sigid sigid)
{
	return in_range(sigid, INTEL_SIGID_GPU_XE_HARDWARE_START, INTEL_SIGID_BATCH);
}

static void cper_init_intel_hdr(struct xe_device *xe, const struct xe_ras_error_class *counter,
				u64 first_timestamp, u32 sig_id, u32 error_count,
				struct xe_cper_intel_hdr *ihdr)
{
	ihdr->counter = *counter;
	ihdr->validation_bits |= XE_CPER_VALID_LOCATION;
	ihdr->sig_id = U32_MAX;

	if (first_timestamp) {
		ihdr->first_timestamp = first_timestamp;
		ihdr->validation_bits |= XE_CPER_VALID_FIRST_TIMESTAMP;
	}

	if (is_sigid(sig_id)) {
		ihdr->sig_id = sig_id;
		ihdr->validation_bits |= XE_CPER_VALID_SIG_ID;
	}

	ihdr->error_count = error_count;

	strscpy(ihdr->pci_bdf, pci_name(to_pci_dev(xe->drm.dev)), sizeof(ihdr->pci_bdf));
	ihdr->validation_bits |= XE_CPER_VALID_PCI_BDF;

#ifdef MODULE
	if (THIS_MODULE->srcversion) {
		strscpy(ihdr->drv_version, THIS_MODULE->srcversion, sizeof(ihdr->drv_version));
		ihdr->validation_bits |= XE_CPER_VALID_DRV_VERSION;
	}
#endif
}

static void cper_emit_counter(struct xe_device *xe, int cper_sev, enum xe_sigid sigid,
			      const struct xe_ras_error_class *counter,
			      const struct xe_ras_get_counter_response *response)
{
	struct xe_cper_intel_hdr ihdr = {};

	cper_init_intel_hdr(xe, counter, response->timestamp,
			    sigid, response->value, &ihdr);
}

static void cper_emit_hw_err(struct xe_device *xe, int cper_sev, enum xe_sigid sigid,
			     const struct xe_ras_error_class *counter)
{
	struct xe_ras_get_counter_response response = {};

	/* Fetching the counter sends a sysctrl command */
	might_sleep();
	xe_device_assert_mem_access(xe);

	if (xe_ras_get_counter_response(xe, counter, &response)) {
		xe_err(xe, "CPER: failed to get counter, skipping record\n");
		return;
	}

	cper_emit_counter(xe, cper_sev, sigid, counter, &response);
}

/**
 * xe_cper_emit() - Emit a CPER record for a SIGID log entry
 * @xe: The &xe_device
 * @cper_sev: CPER severity
 * @sigid: Error signature identifier
 * @component: Component identifier
 * @location: Location details of the @component
 * @data: Pointer to the additional details, or ERR_PTR, or NULL if not applicable
 * @len: Length of the @data in bytes, or 0 if not applicable
 * @vaf: Formatted log message
 *
 * Emit a CPER record for a SIGID log entry
 */
void xe_cper_emit(struct xe_device *xe, int cper_sev, enum xe_sigid sigid,
		  u32 component, u32 location, const void *data, size_t len,
		  struct va_format *vaf)
{
	if (is_hw_sigid(sigid) && !IS_ERR_OR_NULL(data)) {
		cper_emit_hw_err(xe, cper_sev, sigid, data);
		return;
	}

	/* TODO software CPER */
}
