/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell switch driver
 *
 * Copyright (C) 2026 Marvell.
 *
 */
#ifndef SW_NB_V4_H_
#define SW_NB_V4_H_

int sw_nb_v4_fib_event(struct notifier_block *nb,
		       unsigned long event, void *ptr);

int sw_nb_net_v4_neigh_update(struct notifier_block *nb,
			      unsigned long event, void *ptr);

int sw_nb_v4_inetaddr_event(struct notifier_block *nb,
			    unsigned long event, void *ptr);

int sw_nb_v4_netdev_event(struct notifier_block *unused,
			  unsigned long event, void *ptr);
#endif // SW_NB_V4_H__
