// SPDX-License-Identifier: GPL-2.0+
/*
 * Support for hardware timestamping feature for OPEN Alliance
 * 10BASE‑T1x MAC‑PHY Serial Interface framework
 *
 * Author: Selva Rajagopal <selvamani.rajagopal@onsemi.com>
 */

#include <linux/kernel.h>
#include <linux/spi/spi.h>
#include <linux/ptp_clock_kernel.h>
#include <linux/ethtool.h>
#include <linux/phy.h>
#include <linux/oa_tc6.h>

#include "oa_tc6_std_def.h"

/**
 * oa_tc6_ptp_register - Registers clock related callbacks
 * @tc6: oa_tc6 struct.
 * @info: Describes a PTP hardware clock
 *
 * Description: Vendors are expected to set the hardware timestamp
 * related callbacks before calling this function.
 *
 * Return: 0 on success otherwise failed.
 *
 */
int oa_tc6_ptp_register(struct oa_tc6 *tc6, struct ptp_clock_info *info)
{
	int ret = 0;

	/* Not supporting hardware timestamp isn't an error */
	if (!tc6->hw_tstamp_supported)
		return ret;

	snprintf(info->name, sizeof(info->name), "OA TC6 PTP %s",
		 dev_name(&tc6->spi->dev));
	tc6->ptp_clock = ptp_clock_register(info, &tc6->spi->dev);
	if (IS_ERR(tc6->ptp_clock)) {
		ret = PTR_ERR(tc6->ptp_clock);
		tc6->ptp_clock = NULL;
		dev_err(&tc6->spi->dev, "Registration of %s failed\n",
			info->name);
	}

	if (tc6->ptp_clock)
		dev_info(&tc6->spi->dev, "%s registered. index %d\n",
			 info->name, ptp_clock_index(tc6->ptp_clock));
	return ret;
}
EXPORT_SYMBOL_GPL(oa_tc6_ptp_register);

/**
 * oa_tc6_ptp_unregister - Unregisters clock related callbacks
 * @tc6: oa_tc6 struct.
 */
void oa_tc6_ptp_unregister(struct oa_tc6 *tc6)
{
	if (tc6->ptp_clock) {
		ptp_clock_unregister(tc6->ptp_clock);
		tc6->ptp_clock = NULL;
	}
}
EXPORT_SYMBOL_GPL(oa_tc6_ptp_unregister);
