// SPDX-License-Identifier: MIT
/*
 * Copyright © 2026 Intel Corporation
 */

#include <linux/err.h>
#include <linux/minmax.h>

#include "xe_cper.h"
#include "xe_device.h"
#include "xe_ras_types.h"

static bool is_hw_sigid(enum xe_sigid sigid)
{
	return in_range(sigid, INTEL_SIGID_GPU_XE_HARDWARE_START, INTEL_SIGID_BATCH);
}

static void cper_emit_hw_err(struct xe_device *xe, int cper_sev, enum xe_sigid sigid,
			     const struct xe_ras_error_class *counter)
{
	/* TODO */
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
