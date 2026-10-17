// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright 2026 Semiconductor Components Industries, LLC ("onsemi").
 * onsemi's S2500 10BASE-T1S MAC-PHY driver
 */

#include "s2500_hw_def.h"

static int s2500_ptp_get_time64(struct ptp_clock_info *ptp,
				struct timespec64 *ts,
				struct ptp_system_timestamp *ptp_sts)
{
	struct s2500_info *priv = container_of(ptp, struct s2500_info,
					       ptp_clock_info);
	u32 data[2];
	u32 addr;
	int ret;

	ptp_read_system_prets(ptp_sts);
	addr = FIELD_PREP(S2500_REG_MMS_MASK,
			  OA_TC6_PHY_C45_VS_MMS12) |
			  S2500_REG_VS_PTP_SEC;
	ret = oa_tc6_read_registers(priv->tc6, addr, &data[0], 2);
	ptp_read_system_postts(ptp_sts);

	if (!ret) {
		ts->tv_sec = data[0];
		ts->tv_nsec = data[1];
	}

	return ret;
}

static int s2500_ptp_write_time(struct s2500_info *priv,
				const struct timespec64 *ts)
{
	u32 data[2];
	u32 addr;

	lockdep_assert_held(&priv->ptp_adj_lock);

	if (ts->tv_sec >= (1ULL << 32))
		return -ERANGE;

	data[0] = (u32)ts->tv_sec;
	/* bit 31 = execute set command */
	data[1] = ts->tv_nsec | BIT(31);
	addr = FIELD_PREP(S2500_REG_MMS_MASK,
			  OA_TC6_PHY_C45_VS_MMS12) |
			  S2500_REG_VS_PTP_SETSEC;

	return oa_tc6_write_registers(priv->tc6, addr, &data[0], 2);
}

static int s2500_ptp_set_time64(struct ptp_clock_info *ptp,
				const struct timespec64 *ts)
{
	struct s2500_info *priv = container_of(ptp, struct s2500_info,
					       ptp_clock_info);
	int ret;

	mutex_lock(&priv->ptp_adj_lock);
	ret = s2500_ptp_write_time(priv, ts);
	mutex_unlock(&priv->ptp_adj_lock);

	return ret;
}

static int s2500_ptp_set_freq(struct s2500_info *priv, long scaled_ppm)
{
	u32 sign_bit = 0;
	long adj;
	u32 val;
	u64 ppm;

	if (scaled_ppm < 0) {
		/* split sign / mod */
		sign_bit = 1U << 31;
		scaled_ppm = ~scaled_ppm + 1;
	}

	/*
	 * Convert unsigned scaled_ppm to atto-seconds per clock cycles.
	 * The scaled_ppm format is Qx.16 --> 1 lsb = 1/65536 ppm.
	 * The clock period of the S2500 is 8ns (125 MHz), so 1 lsb of
	 * adj register LSB is 1 atto-sec / 8ns = 0.000125 ppm.
	 * Represented in Qx.16 format, this is 0.000125 * 2^16 = 8(.192)
	 * To convert scaled_ppm into a register value we need to divide
	 * it by the LSB value, hence adj = (scaled_ppm * 1000) / 8192 to
	 * minimize the precision loss due to the integer arithmetic.
	 * That further reduces to (scaled_ppm * 125) / 1024.
	 */
	ppm = (u64)scaled_ppm * 125;
	do_div(ppm, 1024);
	adj = (long)ppm;

	/* check overflow */
	if (adj > S2500_PTP_ADJ_MAX)
		return -ERANGE;

	val = (u32)adj | sign_bit;
	return oa_tc6_write_register_mms(priv->tc6, OA_TC6_PHY_C45_VS_MMS12,
					 S2500_REG_VS_PTP_ADJ, val);
}

static int s2500_ptp_adjfine(struct ptp_clock_info *ptp, long scaled_ppm)
{
	struct s2500_info *priv = container_of(ptp, struct s2500_info,
					       ptp_clock_info);

	return s2500_ptp_set_freq(priv, scaled_ppm);
}

static int s2500_ptp_step_time(struct s2500_info *priv, s64 delta)
{
	struct timespec64 target, now, delta_ts;
	struct ptp_system_timestamp sts;
	int ret;

	memset(&sts, 0, sizeof(sts));
	ret = s2500_ptp_get_time64(&priv->ptp_clock_info, &now, &sts);
	if (ret)
		return ret;
	if (delta >= 0) {
		delta_ts = ns_to_timespec64(delta);
		target = timespec64_add(now, delta_ts);
	} else {
		delta_ts = ns_to_timespec64(-delta);
		target = timespec64_sub(now, delta_ts);
	}
	/* The subtraction above can take the target below the epoch */
	if (target.tv_sec < 0)
		return -ERANGE;
	return s2500_ptp_write_time(priv, &target);
}

static int s2500_ptp_adjtime(struct ptp_clock_info *ptp, s64 delta)
{
	struct s2500_info *priv = container_of(ptp, struct s2500_info,
					       ptp_clock_info);
	int ret;

	/* Nothing to do */
	if (delta == 0)
		return 0;

	/* The device has no add-delta register, so the offset is applied as
	 * a read-modify-write of the time registers.
	 */
	mutex_lock(&priv->ptp_adj_lock);
	ret = s2500_ptp_step_time(priv, delta);
	mutex_unlock(&priv->ptp_adj_lock);

	return ret;
}

int s2500_ptp_register(struct s2500_info *priv)
{
	struct ptp_clock_info *info = &priv->ptp_clock_info;
	int ret;

	info->max_adj = S2500_PTP_MAX_ADJ_PPB;
	info->owner = THIS_MODULE;
	info->adjfine = s2500_ptp_adjfine;
	info->gettimex64 = s2500_ptp_get_time64;
	info->settime64 = s2500_ptp_set_time64;
	info->adjtime = s2500_ptp_adjtime;

	ret = oa_tc6_ptp_register(priv->tc6, info);
	if (ret)
		dev_err(&priv->spi->dev, "PTP registration failed\n");
	return ret;
}

