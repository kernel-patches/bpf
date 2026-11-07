/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _RTL8365MB_H
#define _RTL8365MB_H

#include "realtek.h"

enum rtl8365mb_family {
	RTL8365MB_FAMILY_C,
	RTL8365MB_FAMILY_D,
};

enum rtl8365mb_family rtl8365mb_get_family(struct realtek_priv *priv);

static inline bool rtl8365mb_is_d(struct realtek_priv *priv)
{
	return rtl8365mb_get_family(priv) == RTL8365MB_FAMILY_D;
}

#endif /* _RTL8365MB_H */
