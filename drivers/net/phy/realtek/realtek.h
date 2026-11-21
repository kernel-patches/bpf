/* SPDX-License-Identifier: GPL-2.0 */

#ifndef REALTEK_H
#define REALTEK_H

#include <linux/phy.h>

int rtl822x_hwmon_init(struct phy_device *phydev);

#if IS_ENABLED(CONFIG_REALTEK_PHY_PTP)
int rtl8127a_ptp_probe(struct phy_device *phydev);
void rtl8127a_ptp_remove(struct phy_device *phydev);
int rtl8127a_ptp_config_init(struct phy_device *phydev);
#else
static inline int rtl8127a_ptp_probe(struct phy_device *phydev)
{
	return 0;
}

static inline void rtl8127a_ptp_remove(struct phy_device *phydev)
{
}

static inline int rtl8127a_ptp_config_init(struct phy_device *phydev)
{
	return 0;
}
#endif

#endif /* REALTEK_H */
