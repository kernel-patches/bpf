/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _RTL8365MB_H
#define _RTL8365MB_H

#include "realtek.h"

enum rtl8365mb_family {
	RTL8365MB_FAMILY_C,
	RTL8365MB_FAMILY_D,
};

struct rtl8365mb_jam_tbl_entry;

struct rtl8365mb_family_info {
	enum rtl8365mb_family family;
	const struct rtl8365mb_jam_tbl_entry *jam_table;
	size_t jam_size;
	int (*ext_config_forcemode)(struct realtek_priv *priv, int port,
				    bool link, int speed, int duplex,
				    bool tx_pause, bool rx_pause);
};

const struct rtl8365mb_family_info *
rtl8365mb_get_family_info(struct realtek_priv *priv);

static inline bool rtl8365mb_is_d(struct realtek_priv *priv)
{
	return rtl8365mb_get_family_info(priv)->family == RTL8365MB_FAMILY_D;
}

#endif /* _RTL8365MB_H */
