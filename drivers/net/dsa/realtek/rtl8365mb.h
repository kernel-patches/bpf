/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _RTL8365MB_H
#define _RTL8365MB_H

#include "realtek.h"

enum rtl8365mb_family {
	RTL8365MB_FAMILY_C,
	RTL8365MB_FAMILY_D,
};

struct dsa_switch;
struct netlink_ext_ack;
struct rtl8365mb_jam_tbl_entry;
struct rtl8365mb_vlan4k;
struct rtl8365mb_l2_uc;
struct rtl8365mb_l2_mc;

struct rtl8365mb_family_info {
	enum rtl8365mb_family family;
	const struct rtl8365mb_jam_tbl_entry *jam_table;
	size_t jam_size;
	int (*ext_config_forcemode)(struct realtek_priv *priv, int port,
				    bool link, int speed, int duplex,
				    bool tx_pause, bool rx_pause);
	int (*vlan_4k_read)(struct realtek_priv *priv, u16 vid,
			    struct rtl8365mb_vlan4k *vlan4k);
	int (*vlan_4k_write)(struct realtek_priv *priv,
			     const struct rtl8365mb_vlan4k *vlan4k);
	int (*vlan_port_get_pvid)(struct realtek_priv *priv, int port,
				  u16 *pvid);
	int (*vlan_port_reset_pvid)(struct realtek_priv *priv, int port);
	int (*vlan_pvid_port_set)(struct dsa_switch *ds, int port, u16 vid,
				  struct netlink_ext_ack *extack);
	int (*vlan_pvid_port_clear)(struct dsa_switch *ds, int port, u16 vid);
	size_t l2_entry_size;
	void (*l2_data_to_uc)(const u16 *data, struct rtl8365mb_l2_uc *uc);
	void (*l2_uc_to_data)(const struct rtl8365mb_l2_uc *uc, u16 *data);
	void (*l2_data_to_mc)(const u16 *data, struct rtl8365mb_l2_mc *mc);
	void (*l2_mc_to_data)(const struct rtl8365mb_l2_mc *mc, u16 *data);
};

const struct rtl8365mb_family_info *
rtl8365mb_get_family_info(struct realtek_priv *priv);

static inline bool rtl8365mb_is_d(struct realtek_priv *priv)
{
	return rtl8365mb_get_family_info(priv)->family == RTL8365MB_FAMILY_D;
}

#endif /* _RTL8365MB_H */
