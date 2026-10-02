/* SPDX-License-Identifier: GPL-2.0 */
/* QoS and DCB configuration for the rtl8365mb switch family */

#ifndef _REALTEK_RTL8365MB_DCB_H
#define _REALTEK_RTL8365MB_DCB_H

#include <linux/types.h>
#include <net/dsa.h>

/* The switch has eight internal priorities (0..7). The egress queue count is
 * a per-chip property; see struct rtl8365mb_chip_info::num_tx_queues.
 */
#define RTL8365MB_NUM_IPMS		8

int rtl8365mb_dcb_init(struct dsa_switch *ds);
int rtl8365mb_dcb_init_port(struct dsa_switch *ds, int port);
int rtl8365mb_port_get_default_prio(struct dsa_switch *ds, int port);
int rtl8365mb_port_set_default_prio(struct dsa_switch *ds, int port, u8 prio);
int rtl8365mb_port_get_apptrust(struct dsa_switch *ds, int port, u8 *sel,
				int *nsel);
int rtl8365mb_port_set_apptrust(struct dsa_switch *ds, int port, const u8 *sel,
				int nsel);

#endif /* _REALTEK_RTL8365MB_DCB_H */
