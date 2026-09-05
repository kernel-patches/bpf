/* SPDX-License-Identifier: GPL-2.0 */
/*
 * SiTime SiT9531x DPLL subsystem interface
 *
 * Copyright (C) 2026 SiTime Corp.
 * Author: Ali Rouhi <arouhi@sitime.com>
 * Author: Oleg Zadorozhnyi <Oleg.Zadorozhnyi@devoxsoftware.com>
 *
 * DPLL device and pin structures, and function declarations for
 * the DPLL registration and callback layer.
 */

#ifndef _SIT9531X_DPLL_H
#define _SIT9531X_DPLL_H

#include <linux/dpll.h>
#include <linux/list.h>
#include <linux/types.h>

struct sit9531x_dev;

/* Per-pin DPLL state. */
struct sit9531x_dpll_pin {
	struct list_head		list;
	struct sit9531x_dpll		*dpll;
	struct dpll_pin			*dpll_pin;
	dpll_tracker			tracker;
	struct fwnode_handle		*fwnode;
	char				label[8];	/* "IN0", "OUT3" */
	enum dpll_pin_direction		dir;
	u8				id;		/* hardware index */
	u8				prio;
	enum dpll_pin_state		pin_state;
	s32				phase_adjust;	/* picoseconds */
	s64				phase_offset;	/* picoseconds */
	bool				esync_control;
	u64				esync_freq;	/* 0 == disabled */
};

/* Per-PLL DPLL device state. */
struct sit9531x_dpll {
	struct list_head		list;
	struct sit9531x_dev		*dev;
	struct dpll_device		*dpll_dev;
	dpll_tracker			tracker;
	struct dpll_device_ops		ops;	/* per-instance copy */
	struct list_head		pins;
	u8				id;	/* 0 = PLLA .. 3 = PLLD */
	enum dpll_lock_status		lock_status;
};

/* ---- DPLL allocation and registration ---- */
/*
 * The callback tables stay with the callbacks; the registration code that
 * hands them to the subsystem lives next to probe() in core.c.
 */
extern const struct dpll_device_ops sit9531x_dpll_device_ops;
const struct dpll_pin_ops *
sit9531x_dpll_pin_ops_get(const struct sit9531x_dpll_pin *pin);

struct sit9531x_dpll *sit9531x_dpll_alloc(struct sit9531x_dev *sitdev, u8 ch);
void sit9531x_dpll_free(struct sit9531x_dpll *sitdpll);
int  sit9531x_dpll_register(struct sit9531x_dpll *sitdpll);
void sit9531x_dpll_unregister(struct sit9531x_dpll *sitdpll);

/* ---- Periodic change detection ---- */
void sit9531x_dpll_changes_check(struct sit9531x_dpll *sitdpll);

#endif /* _SIT9531X_DPLL_H */
