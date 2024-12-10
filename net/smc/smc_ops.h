/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  Shared Memory Communications over RDMA (SMC-R) and RoCE
 *
 *  Generic hook for SMC subsystem.
 *
 *  Copyright IBM Corp. 2016
 *  Copyright (c) 2024, Alibaba Inc.
 *
 *  Author: D. Wythe <alibuda@linux.alibaba.com>
 */

#ifndef __SMC_OPS
#define __SMC_OPS

#include <net/smc.h>

#if IS_ENABLED(CONFIG_SMC_OPS)
/* Find ops by the target name, which required to be a c-string.
 * Return NULL if no such ops was found,otherwise, return a valid ops.
 *
 * Note: Caller MUST ensure it's was invoked under rcu_read_lock.
 */
struct smc_ops *smc_ops_find_by_name(const char *name);
#else
static inline struct smc_ops *smc_ops_find_by_name(const char *name) { return NULL; }
#endif /* CONFIG_SMC_OPS*/

#endif /* __SMC_OPS */
