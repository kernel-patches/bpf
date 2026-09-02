/* SPDX-License-Identifier: GPL-2.0 */
/*
 * SiTime SiT9531x firmware node property parsing
 *
 * Copyright (C) 2026 SiTime Corp.
 * Author: Ali Rouhi <arouhi@sitime.com>
 * Author: Oleg Zadorozhnyi <Oleg.Zadorozhnyi@devoxsoftware.com>
 */

#ifndef _SIT9531X_PROP_H
#define _SIT9531X_PROP_H

#include <linux/dpll.h>
#include <linux/fwnode.h>

struct sit9531x_dev;

/*
 * struct sit9531x_pin_props - pin properties from firmware
 * @fwnode:		firmware node handle (NULL if no DT node)
 * @dpll_props:		DPLL core pin properties
 * @package_label:	pin package label (e.g. "IN0", "OUT3")
 * @esync_control:	embedded sync is controllable
 */
struct sit9531x_pin_props {
	struct fwnode_handle		*fwnode;
	struct dpll_pin_properties	dpll_props;
	char				package_label[8];
	bool				esync_control;
};

enum dpll_type sit9531x_prop_dpll_type_get(struct sit9531x_dev *sitdev,
					   u8 index);
struct sit9531x_pin_props *sit9531x_pin_props_get(struct sit9531x_dev *sitdev,
						  enum dpll_pin_direction dir,
						  u8 index);
void sit9531x_pin_props_put(struct sit9531x_pin_props *props);

#endif /* _SIT9531X_PROP_H */
