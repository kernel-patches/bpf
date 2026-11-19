/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2026 Intel Corporation
 */

#ifndef _XE_WEDGE_H_
#define _XE_WEDGE_H_

#include <linux/atomic.h>
#include <linux/types.h>

#include "xe_device_types.h"
#include "xe_wedge_types.h"

static inline bool xe_wedged(struct xe_device *xe)
{
	return atomic_read(&xe->wedged.ref);
}

/*
 * Do not abuse this. Prefer xe_wedged() where possible. Only use this
 * as a last resort where xe_wedged() is problematic.
 */
static inline bool xe_wedged_permanent(struct xe_device *xe)
{
	return atomic_read(&xe->wedged.perm);
}

void xe_wedge_declare(struct xe_device *xe, unsigned long method);
int xe_wedge_init(struct xe_device *xe);
int xe_wedge_set_mode(struct xe_device *xe, enum xe_wedged_mode mode);
void xe_wedge_get(struct xe_device *xe);
void xe_wedge_put(struct xe_device *xe);

#endif
