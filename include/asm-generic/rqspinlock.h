/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Resilient Queued Spin Lock
 *
 * (C) Copyright 2024 Meta Platforms, Inc. and affiliates.
 *
 * Authors: Kumar Kartikeya Dwivedi <memxor@gmail.com>
 */
#ifndef __ASM_GENERIC_RQSPINLOCK_H
#define __ASM_GENERIC_RQSPINLOCK_H

#include <linux/types.h>

struct qspinlock;

extern void resilient_queued_spin_lock_slowpath(struct qspinlock *lock, u32 val);

#endif /* __ASM_GENERIC_RQSPINLOCK_H */
