/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2026 Intel Corporation
 */

#ifndef _XE_CPER_TYPES_H_
#define _XE_CPER_TYPES_H_

#include <linux/types.h>

#include "xe_ras_types.h"

/*
 * Validation bits definition for validation_bits in struct
 * xe_cper_intel_hdr. When set, corresponding fields in header
 * contains valid data
 */
#define XE_CPER_VALID_LOCATION		0x0001
#define XE_CPER_VALID_FIRST_TIMESTAMP	0x0002
#define XE_CPER_VALID_SIG_ID		0x0004
#define XE_CPER_VALID_PCI_BDF		0x0008
#define XE_CPER_VALID_DRV_VERSION	0x0010

/**
 * struct xe_cper_intel_hdr - Intel-specific CPER header
 *
 * Fixed-size header for the Intel GPU error section of a CPER record.
 * All multi-byte fields are little-endian.
 */
struct xe_cper_intel_hdr {
	/** @counter: Error class (severity, component, location, cause) */
	struct xe_ras_error_class counter;
	/** @first_timestamp: First occurrence of this error class, in ticks */
	u64 first_timestamp;
	/** @sig_id: Aggregated error class SIG ID; set to U32_MAX if unknown */
	u32 sig_id;
	/** @error_count: Number of times this error has been observed */
	u32 error_count;
	/** @validation_bits: Raw u16 view of all valid bits */
	u16 validation_bits;
	/** @pci_bdf: PCI location string, format "DDDD:bb:dd.f" */
	char pci_bdf[16];
	/** @drv_version: Driver source version string (THIS_MODULE->srcversion) */
	char drv_version[25];
	/** @reserved: Reserved for future use, must be zero */
	u8 reserved[261];
} __packed;

#endif
