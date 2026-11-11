// SPDX-License-Identifier: GPL-2.0+
/*
 * PTP hardware clock support for the internal PHY of RTL8127A
 */

#include <linux/bitfield.h>
#include <linux/bits.h>
#include <linux/iopoll.h>
#include <linux/math64.h>
#include <linux/netdevice.h>
#include <linux/phy.h>
#include <linux/ptp_clock_kernel.h>
#include <linux/timekeeping.h>

#include "realtek.h"

#define RTL8127A_PTP_CTL		0xe400
#define  RTL8127A_PTP_CTL_EN		BIT(0)
#define  RTL8127A_PTP_CTL_TYPE_3	0x003f
#define RTL8127A_PTP_INER		0xe402
#define RTL8127A_PTP_INSR		0xe404
#define  RTL8127A_PTP_INT_RX_TS		BIT(2)
#define  RTL8127A_PTP_INT_TX_TS		BIT(3)
#define RTL8127A_PTP_SYNCE_CTL		0xe406
#define  RTL8127A_PTP_SYNCE_EN		BIT(0)
#define RTL8127A_PTP_GEN_CFG		0xe408
#define  RTL8127A_PTP_INT_CLR_MODE	BIT(0)
#define RTL8127A_PTP_CLK_CFG		0xe410
#define  RTL8127A_PTP_CLK_CFG_EXEC	BIT(0)
#define  RTL8127A_PTP_CLK_CFG_MODE	GENMASK(3, 1)
/* Time registers */
#define RTL8127A_PTP_CFG_TIME		0xe412
#define  RTL8127A_PTP_NS_LO		0x0
#define  RTL8127A_PTP_NS_HI		0x2
#define  RTL8127A_PTP_S_LO		0x4
#define  RTL8127A_PTP_S_MI		0x6
#define  RTL8127A_PTP_S_HI		0x8
#define  RTL8127A_PTP_NS_HI_MASK	GENMASK(13, 0)
#define  RTL8127A_PTP_NSEC_MASK		GENMASK(29, 0)
#define  RTL8127A_PTP_SEC_MASK		GENMASK_ULL(47, 0)
#define  RTL8127A_PTP_RATE_HI_MASK	GENMASK(21, 16)

#define RTL8127A_PTP_MAX_ADJ		488281

/* RTL8127A_PTP_CLK_CFG clock adjust modes */
enum rtl8127a_ptp_clkadj_mode {
	RTL8127A_PTP_DIRECT_READ	= 4,
	RTL8127A_PTP_DIRECT_WRITE	= 6,
	RTL8127A_PTP_INC_STEP		= 8,
	RTL8127A_PTP_DEC_STEP		= 10,
	RTL8127A_PTP_RATE_WRITE		= 14,
};

struct rtl8127a_ptp {
	struct phy_device *phydev;
	struct ptp_clock_info info;
	struct ptp_clock *clock;
	struct mutex lock;	/* serializes PTP register access sequences */
};

static int rtl8127a_ptp_read(struct rtl8127a_ptp *ptp, u16 reg)
{
	return phy_read_mmd(ptp->phydev, MDIO_MMD_VEND2, reg);
}

static int rtl8127a_ptp_write(struct rtl8127a_ptp *ptp, u16 reg, u16 val)
{
	return phy_write_mmd(ptp->phydev, MDIO_MMD_VEND2, reg, val);
}

/* Unlike phy_modify_mmd() always write the register back, some of the
 * bits are commands to the PTP block.
 */
static int rtl8127a_ptp_modify(struct rtl8127a_ptp *ptp, u16 reg, u16 mask,
			       u16 set)
{
	int val = rtl8127a_ptp_read(ptp, reg);

	if (val < 0)
		return val;

	return rtl8127a_ptp_write(ptp, reg, (val & ~mask) | set);
}

/* Poll until (reg & mask) is non-zero (set == true) or zero (set == false).
 * Returns the last register value read, or a negative error code.
 */
static int rtl8127a_ptp_poll(struct rtl8127a_ptp *ptp, u16 reg, u16 mask,
			     bool set)
{
	int ret, val;

	ret = read_poll_timeout(rtl8127a_ptp_read, val,
				val < 0 || !!(val & mask) == set, 1, 1000,
				false, ptp, reg);
	if (val < 0)
		ret = val;
	if (ret) {
		if (net_ratelimit())
			phydev_err(ptp->phydev,
				   "PTP reg 0x%04x poll failed: %d\n", reg, ret);
		return ret;
	}

	return val;
}

static int rtl8127a_ptp_clkadj(struct rtl8127a_ptp *ptp,
			       enum rtl8127a_ptp_clkadj_mode mode)
{
	int ret;

	ret = rtl8127a_ptp_modify(ptp, RTL8127A_PTP_CLK_CFG,
				  RTL8127A_PTP_CLK_CFG_MODE,
				  RTL8127A_PTP_CLK_CFG_EXEC | mode);
	if (ret)
		return ret;

	ret = rtl8127a_ptp_poll(ptp, RTL8127A_PTP_CLK_CFG,
				RTL8127A_PTP_CLK_CFG_EXEC, false);

	return ret < 0 ? ret : 0;
}

static int rtl8127a_ptp_read_time(struct rtl8127a_ptp *ptp, u16 base,
				  struct timespec64 *ts)
{
	static const u16 regs[] = {
		RTL8127A_PTP_NS_HI, RTL8127A_PTP_NS_LO,
		RTL8127A_PTP_S_HI, RTL8127A_PTP_S_MI, RTL8127A_PTP_S_LO,
	};
	int val[ARRAY_SIZE(regs)];
	int i;

	for (i = 0; i < ARRAY_SIZE(regs); i++) {
		val[i] = rtl8127a_ptp_read(ptp, base + regs[i]);
		if (val[i] < 0)
			return val[i];
	}

	ts->tv_nsec = (val[0] & RTL8127A_PTP_NS_HI_MASK) << 16 | val[1];
	ts->tv_sec = (u64)val[2] << 32 | (u64)val[3] << 16 | val[4];

	return 0;
}

static int rtl8127a_ptp_write_time(struct rtl8127a_ptp *ptp,
				   const struct timespec64 *ts)
{
	u64 sec = ts->tv_sec & RTL8127A_PTP_SEC_MASK;
	u32 nsec = ts->tv_nsec & RTL8127A_PTP_NSEC_MASK;
	const struct {
		u16 reg;
		u16 val;
	} regs[] = {
		{ RTL8127A_PTP_NS_LO, nsec },
		{ RTL8127A_PTP_NS_HI, nsec >> 16 },
		{ RTL8127A_PTP_S_LO, sec },
		{ RTL8127A_PTP_S_MI, sec >> 16 },
		{ RTL8127A_PTP_S_HI, sec >> 32 },
	};
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(regs); i++) {
		ret = rtl8127a_ptp_write(ptp, RTL8127A_PTP_CFG_TIME + regs[i].reg,
					 regs[i].val);
		if (ret)
			return ret;
	}

	return 0;
}

static int rtl8127a_ptp_hwtstamp_enable(struct rtl8127a_ptp *ptp, bool enable)
{
	int ret;

	mutex_lock(&ptp->lock);

	ret = rtl8127a_ptp_modify(ptp, RTL8127A_PTP_SYNCE_CTL,
				  RTL8127A_PTP_SYNCE_EN, 0);
	if (ret)
		goto out;

	if (enable) {
		ret = rtl8127a_ptp_modify(ptp, RTL8127A_PTP_INER, 0,
					  RTL8127A_PTP_INT_RX_TS |
					  RTL8127A_PTP_INT_TX_TS);
		if (ret)
			goto out;

		ret = rtl8127a_ptp_modify(ptp, RTL8127A_PTP_GEN_CFG, 0,
					  RTL8127A_PTP_INT_CLR_MODE);
		if (ret)
			goto out;

		ret = rtl8127a_ptp_write(ptp, RTL8127A_PTP_INSR, 0xffff);
		if (ret)
			goto out;

		ret = rtl8127a_ptp_write(ptp, RTL8127A_PTP_CTL,
					 RTL8127A_PTP_CTL_TYPE_3 | BIT(12));
	} else {
		ret = rtl8127a_ptp_modify(ptp, RTL8127A_PTP_INER,
					  RTL8127A_PTP_INT_RX_TS |
					  RTL8127A_PTP_INT_TX_TS, 0);
		if (ret)
			goto out;

		ret = rtl8127a_ptp_modify(ptp, RTL8127A_PTP_CTL,
					  RTL8127A_PTP_CTL_EN, 0);
	}
	if (ret)
		goto out;

	ret = rtl8127a_ptp_modify(ptp, 0xa640, 0, BIT(15));
out:
	mutex_unlock(&ptp->lock);

	return ret;
}

static int rtl8127a_ptp_settime(struct rtl8127a_ptp *ptp,
				const struct timespec64 *ts)
{
	int ret;

	mutex_lock(&ptp->lock);
	ret = rtl8127a_ptp_write_time(ptp, ts);
	if (!ret)
		ret = rtl8127a_ptp_clkadj(ptp, RTL8127A_PTP_DIRECT_WRITE);
	mutex_unlock(&ptp->lock);

	return ret;
}

static int rtl8127a_ptp_adjfine(struct ptp_clock_info *info, long scaled_ppm)
{
	struct rtl8127a_ptp *ptp = container_of(info, struct rtl8127a_ptp, info);
	s32 ppb = scaled_ppm_to_ppb(scaled_ppm);
	u32 rate;
	int ret;

	rate = div_u64((u64)abs(ppb) << 32, NSEC_PER_SEC);
	if (ppb < 0)
		rate = -rate;

	mutex_lock(&ptp->lock);
	ret = rtl8127a_ptp_write(ptp, RTL8127A_PTP_CFG_TIME + RTL8127A_PTP_NS_LO,
				 rate);
	if (ret)
		goto out;

	ret = rtl8127a_ptp_write(ptp, RTL8127A_PTP_CFG_TIME + RTL8127A_PTP_NS_HI,
				 FIELD_GET(RTL8127A_PTP_RATE_HI_MASK, rate));
	if (ret)
		goto out;

	ret = rtl8127a_ptp_clkadj(ptp, RTL8127A_PTP_RATE_WRITE);
out:
	mutex_unlock(&ptp->lock);

	return ret;
}

static int rtl8127a_ptp_adjtime(struct ptp_clock_info *info, s64 delta)
{
	struct rtl8127a_ptp *ptp = container_of(info, struct rtl8127a_ptp, info);
	struct timespec64 d = ns_to_timespec64(abs(delta));
	int ret;

	mutex_lock(&ptp->lock);
	ret = rtl8127a_ptp_write_time(ptp, &d);
	if (!ret)
		ret = rtl8127a_ptp_clkadj(ptp, delta < 0 ?
						RTL8127A_PTP_DEC_STEP :
						RTL8127A_PTP_INC_STEP);
	mutex_unlock(&ptp->lock);

	return ret;
}

static int rtl8127a_ptp_gettimex64(struct ptp_clock_info *info,
				   struct timespec64 *ts,
				   struct ptp_system_timestamp *sts)
{
	struct rtl8127a_ptp *ptp = container_of(info, struct rtl8127a_ptp, info);
	int ret;

	mutex_lock(&ptp->lock);
	ptp_read_system_prets(sts);
	ret = rtl8127a_ptp_clkadj(ptp, RTL8127A_PTP_DIRECT_READ);
	ptp_read_system_postts(sts);
	if (!ret)
		ret = rtl8127a_ptp_read_time(ptp, RTL8127A_PTP_CFG_TIME, ts);
	mutex_unlock(&ptp->lock);

	return ret;
}

static int rtl8127a_ptp_settime64(struct ptp_clock_info *info,
				  const struct timespec64 *ts)
{
	struct rtl8127a_ptp *ptp = container_of(info, struct rtl8127a_ptp, info);

	return rtl8127a_ptp_settime(ptp, ts);
}

static const struct ptp_clock_info rtl8127a_ptp_info = {
	.owner		= THIS_MODULE,
	.name		= "RTL8127A PHC",
	.max_adj	= RTL8127A_PTP_MAX_ADJ,
	.adjfine	= rtl8127a_ptp_adjfine,
	.adjtime	= rtl8127a_ptp_adjtime,
	.gettimex64	= rtl8127a_ptp_gettimex64,
	.settime64	= rtl8127a_ptp_settime64,
};

int rtl8127a_ptp_config_init(struct phy_device *phydev)
{
	struct rtl8127a_ptp *ptp = phydev->priv;
	struct timespec64 ts;

	if (!ptp)
		return 0;

	/* (Re)start the clock from the system time whenever the PHY is
	 * (re)initialized, e.g. each time the MAC driver brings it up.
	 */
	ktime_get_real_ts64(&ts);

	return rtl8127a_ptp_settime(ptp, &ts);
}

int rtl8127a_ptp_probe(struct phy_device *phydev)
{
	struct device *dev = &phydev->mdio.dev;
	struct rtl8127a_ptp *ptp;
	int ret;

	ptp = devm_kzalloc(dev, sizeof(*ptp), GFP_KERNEL);
	if (!ptp)
		return -ENOMEM;

	ret = devm_mutex_init(dev, &ptp->lock);
	if (ret)
		return ret;

	ptp->phydev = phydev;
	ptp->info = rtl8127a_ptp_info;

	ret = rtl8127a_ptp_hwtstamp_enable(ptp, false);
	if (ret)
		return ret;

	ptp->clock = ptp_clock_register(&ptp->info, dev);
	if (IS_ERR(ptp->clock))
		return PTR_ERR(ptp->clock);

	phydev->priv = ptp;

	return 0;
}

void rtl8127a_ptp_remove(struct phy_device *phydev)
{
	struct rtl8127a_ptp *ptp = phydev->priv;

	if (!ptp)
		return;

	rtl8127a_ptp_hwtstamp_enable(ptp, false);
	ptp_clock_unregister(ptp->clock);
}
