/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2026 Intel Corporation
 */

#ifndef _XE_CPER_H_
#define _XE_CPER_H_

#include <linux/types.h>

#include "abi/xe_sigid_abi.h"

struct va_format;
struct xe_device;

#if IS_ENABLED(CONFIG_UEFI_CPER)
void xe_cper_emit(struct xe_device *xe, int cper_sev, enum xe_sigid sigid,
		  u32 component, u32 location, const void *data, size_t len,
		  struct va_format *vaf);
#else
static inline void xe_cper_emit(struct xe_device *xe, int cper_sev, enum xe_sigid sigid,
				u32 component, u32 location, const void *data, size_t len,
				struct va_format *vaf) {}
#endif

#endif /* _XE_CPER_H_ */
