/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2026 Intel Corporation
 */

#ifndef _XE_CPER_TYPES_H_
#define _XE_CPER_TYPES_H_

#include <linux/cper.h>
#include <linux/types.h>
#include <linux/uuid.h>

#include "xe_ras_types.h"

/* Entries built from RAS error logs carry fixed-size details */
#define XE_CPER_INTEL_EVENT_SIZE \
	(offsetof(struct xe_cper_intel_event, metadata) + \
	 sizeof_field(struct xe_ras_error_log, details))

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

/*
 * Intel CPER GUID Namespace — RFC 9562 UUIDv5 (SHA-1 name-based)
 *
 * All values below are generated deterministically by uuid generator.
 * Do not hand-edit the byte values.
 */

/* Creator IDs */
#define INTEL_CPER_CREATOR_XEKMD \
	GUID_INIT(0x9a42070f, 0xdf9d, 0x555e, \
		  0xba, 0x02, 0x7c, 0xbc, 0x86, 0x3d, 0x37, 0x1c)

/* Notification Types */
#define INTEL_CPER_NOTIFY_GPU_ERROR \
	GUID_INIT(0x4ae12aef, 0x8745, 0x5fc7, \
		  0xb9, 0x96, 0x71, 0xee, 0xbb, 0x51, 0xf2, 0x23)

/* Section Types */
#define INTEL_CPER_SECTION_ACCEL_GENERIC \
	GUID_INIT(0xea9d8f84, 0x4258, 0x5227, \
		  0x80, 0x28, 0xb9, 0xb1, 0x3e, 0x6d, 0x58, 0xb0)

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
	u8 reserved[258];
	/** @einfo_size: Size of xe_cper_intel_info */
	u16 einfo_size;
	/** @reserved1: Reserved for future use, must be zero */
	u8 reserved1;
} __packed;

/**
 * struct xe_cper_intel_info - Variable-length Intel-specific CPER error information
 *
 * Contains the counter and event queue, and is appended after
 * &xe_cper_intel_hdr when detailed error information is available.
 */
struct xe_cper_intel_info {
	/** @counter: Error class (severity, component, location, cause) */
	struct xe_ras_error_class counter;
	/** @error_count: Total number of errors recorded */
	u32 error_count;
	/** @event_queue_size: Total size of @event_queue in bytes */
	u32 event_queue_size;
	/** @event_queue_count: Number of events in @event_queue */
	u32 event_queue_count;
	/** @event_queue: Packed array of xe_cper_intel_event records */
	u8 event_queue[];
} __packed;

/**
 * struct xe_cper_intel_event - Single error event in the CPER event queue
 */
struct xe_cper_intel_event {
	/** @size: Byte size of the @metadata payload */
	u32 size;
	/** @timestamp: &xe_ras_error_log::timestamp */
	u64 timestamp;
	/** @metadata: &xe_ras_error_log::details */
	u8 metadata[];
} __packed;

/**
 * struct xe_cper_nonstd_record - Intel GPU CPER record
 *
 * Contains the standard CPER record header, section descriptor, and the
 * Intel section header. A &xe_cper_intel_info payload may be
 * appended dynamically.
 */
struct xe_cper_nonstd_record {
	/** @record_hdr: Standard CPER record header (UEFI Appendix N.2.1) */
	struct cper_record_header record_hdr;
	/** @section_desc: CPER section descriptor */
	struct cper_section_descriptor section_desc;
	/** @intel_hdr: Intel-specific CPER header */
	struct xe_cper_intel_hdr intel_hdr;
} __packed;

/**
 * struct xe_device_guid_entry - Mapping from PCI device ID to CPER device GUID
 *
 * Used to resolve the platform_id field in a CPER record header.
 * GUIDs are UUIDv5 (RFC 9562, SHA-1) derived from the Intel CPER namespace
 * with name string "platform/8086:<dev_id_hex_lower>".
 */
struct xe_device_guid_entry {
	/** @device_id: PCI device ID */
	u16       device_id;
	/** @guid: Corresponding UUIDv5 device GUID */
	guid_t    guid;
};

/**
 * struct xe_cper_info_entry - One CPER info payload and its source counter
 */
struct xe_cper_info_entry {
	/** @hdr: Error class and error count used for the CPER section header */
	struct xe_ras_dynamic_counter_hdr hdr;
	/** @einfo: Allocated info payload, NULL if none */
	struct xe_cper_intel_info *einfo;
	/** @einfo_size: Byte size of @einfo including the event queue */
	u32 einfo_size;
	/** @timestamp: Timestamp of the first occurrence of this error class */
	u64 timestamp;
};

/**
 * struct xe_cper - Xe CPER state
 */
struct xe_cper {
	/** @on_query: Emit a CPER record on each RAS counter query */
	bool on_query;
};

#endif
