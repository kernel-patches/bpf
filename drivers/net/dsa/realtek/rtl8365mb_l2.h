/* SPDX-License-Identifier: GPL-2.0 */
/* Forwarding and multicast database interface for the rtl8365mb switch family
 *
 * Copyright (C) 2022 Alvin Šipraga <alsi@bang-olufsen.dk>
 */

#ifndef _REALTEK_RTL8365MB_L2_H
#define _REALTEK_RTL8365MB_L2_H

#include <linux/if_ether.h>
#include <linux/types.h>

#include "realtek.h"

#define RTL8365MB_C_L2_ENTRY_SIZE		6
#define RTL8365MB_D_L2_ENTRY_SIZE		5
/* Highest L2 entry size of any supported chip, used for sizing */
#define RTL8365MB_L2_ENTRY_SIZE			RTL8365MB_C_L2_ENTRY_SIZE

struct rtl8365mb_l2_uc;
struct rtl8365mb_l2_mc;

void rtl8365mb_c_l2_data_to_uc(const u16 *data, struct rtl8365mb_l2_uc *uc);
void rtl8365mb_c_l2_uc_to_data(const struct rtl8365mb_l2_uc *uc, u16 *data);
void rtl8365mb_c_l2_data_to_mc(const u16 *data, struct rtl8365mb_l2_mc *mc);
void rtl8365mb_c_l2_mc_to_data(const struct rtl8365mb_l2_mc *mc, u16 *data);

void rtl8365mb_d_l2_data_to_uc(const u16 *data, struct rtl8365mb_l2_uc *uc);
void rtl8365mb_d_l2_uc_to_data(const struct rtl8365mb_l2_uc *uc, u16 *data);
void rtl8365mb_d_l2_data_to_mc(const u16 *data, struct rtl8365mb_l2_mc *mc);
void rtl8365mb_d_l2_mc_to_data(const struct rtl8365mb_l2_mc *mc, u16 *data);

int rtl8365mb_l2_get_next_uc(struct realtek_priv *priv, u16 *addr, int port,
			     struct realtek_fdb_entry *entry);
int rtl8365mb_l2_add_uc(struct realtek_priv *priv, int port,
			const unsigned char addr[static ETH_ALEN],
			u16 efid, u16 vid);
int rtl8365mb_l2_del_uc(struct realtek_priv *priv, int port,
			const unsigned char addr[static ETH_ALEN],
			u16 efid, u16 vid);
int rtl8365mb_l2_flush(struct realtek_priv *priv, int port, u16 vid);

int rtl8365mb_l2_add_mc(struct realtek_priv *priv, int port,
			const unsigned char mac_addr[static ETH_ALEN],
			u16 vid);
int rtl8365mb_l2_del_mc(struct realtek_priv *priv, int port,
			const unsigned char mac_addr[static ETH_ALEN],
			u16 vid);

#endif /* _REALTEK_RTL8365MB_L2_H */
