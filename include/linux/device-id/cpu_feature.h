/* SPDX-License-Identifier: GPL-2.0 */
#ifndef LINUX_DEVICE_ID_CPU_FEATURE_H
#define LINUX_DEVICE_ID_CPU_FEATURE_H

/*
 * This file is included by scripts/mod/file2alias.c which is compiled
 * using the host compiler which might not have <linux/types.h> but the
 * __u{8,16,32} types are defined there locally.
 */
#ifdef __KERNEL__
#include <linux/types.h>
#endif

/*
 * Generic table type for matching CPU features.
 * @feature:	the bit number of the feature (0 - 65535)
 */

struct cpu_feature {
	__u16	feature;
};

#endif /* ifndef LINUX_DEVICE_ID_CPU_FEATURE_H */
