// SPDX-License-Identifier: GPL-2.0+
/*
 * PTP hardware clock and timestamping support for the internal PHY of
 * RTL8127A
 */

#include <linux/bitfield.h>
#include <linux/bits.h>
#include <linux/iopoll.h>
#include <linux/math64.h>
#include <linux/netdevice.h>
#include <linux/phy.h>
#include <linux/ptp_classify.h>
#include <linux/ptp_clock_kernel.h>
#include <linux/skbuff.h>
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
#define RTL8127A_PTP_TRX_TS_STA		0xe430
#define  RTL8127A_PTP_TRX_TS_RD		BIT(0)
#define  RTL8127A_PTP_TRX_TS_SEL_RX	BIT(1)
#define  RTL8127A_PTP_TRX_TS_MSGTYPE	GENMASK(3, 2)
#define  RTL8127A_PTP_TRX_TS_EXEC	BIT(4)
#define  RTL8127A_PTP_TX_PDLYRSP_RDY	BIT(12)
#define  RTL8127A_PTP_TX_PDLYREQ_RDY	BIT(13)
#define  RTL8127A_PTP_TX_DLYREQ_RDY	BIT(14)
#define  RTL8127A_PTP_TX_SYNC_RDY	BIT(15)
#define  RTL8127A_PTP_TX_RDY		GENMASK(15, 12)
/* Time registers, CFG_TIME for the clock, TRX_TS_TIME for packets */
#define RTL8127A_PTP_CFG_TIME		0xe412
#define RTL8127A_PTP_TRX_TS_TIME	0xe446
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
#define RTL8127A_PTP_TX_TIMEOUT		(15 * HZ)

/* RTL8127A_PTP_CLK_CFG clock adjust modes */
enum rtl8127a_ptp_clkadj_mode {
	RTL8127A_PTP_DIRECT_READ	= 4,
	RTL8127A_PTP_DIRECT_WRITE	= 6,
	RTL8127A_PTP_INC_STEP		= 8,
	RTL8127A_PTP_DEC_STEP		= 10,
	RTL8127A_PTP_RATE_WRITE		= 14,
};

/* ptp->state bits */
enum rtl8127a_ptp_state {
	RTL8127A_PTP_TX_IN_PROGRESS,
};

struct rtl8127a_ptp_skb_cb {
	u8 msgtype;
};

#define RTL8127A_PTP_SKB_CB(skb) \
	((struct rtl8127a_ptp_skb_cb *)(skb)->cb)

struct rtl8127a_ptp {
	struct phy_device *phydev;
	struct mii_timestamper mii_ts;
	struct ptp_clock_info info;
	struct ptp_clock *clock;
	struct mutex lock;	/* serializes PTP register access sequences */
	enum hwtstamp_tx_types tx_type;
	enum hwtstamp_rx_filters rx_filter;
	bool rx_enabled;
	struct sk_buff_head rx_queue;
	struct sk_buff *tx_skb;
	unsigned long tx_start;
	unsigned long state;
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

/* Latch the RX or TX timestamp of the given message type into the
 * RTL8127A_PTP_TRX_TS_TIME registers.
 */
static int rtl8127a_ptp_trx_ts_cmd(struct rtl8127a_ptp *ptp, u16 cmd)
{
	int ret;

	ret = rtl8127a_ptp_modify(ptp, RTL8127A_PTP_TRX_TS_STA,
				  RTL8127A_PTP_TRX_TS_SEL_RX |
				  RTL8127A_PTP_TRX_TS_MSGTYPE,
				  RTL8127A_PTP_TRX_TS_RD | cmd);
	if (ret)
		return ret;

	ret = rtl8127a_ptp_poll(ptp, RTL8127A_PTP_TRX_TS_STA,
				RTL8127A_PTP_TRX_TS_RD, false);

	return ret < 0 ? ret : 0;
}

static int rtl8127a_ptp_egress_time(struct rtl8127a_ptp *ptp,
				    struct timespec64 *ts)
{
	u8 msgtype;
	int val;
	int ret;

	val = rtl8127a_ptp_poll(ptp, RTL8127A_PTP_TRX_TS_STA,
				RTL8127A_PTP_TX_RDY, true);
	if (val < 0)
		val = 0;

	switch (val & RTL8127A_PTP_TX_RDY) {
	case RTL8127A_PTP_TX_PDLYRSP_RDY:
		msgtype = PTP_MSGTYPE_PDELAY_RESP;
		break;
	case RTL8127A_PTP_TX_PDLYREQ_RDY:
		msgtype = PTP_MSGTYPE_PDELAY_REQ;
		break;
	case RTL8127A_PTP_TX_DLYREQ_RDY:
		msgtype = PTP_MSGTYPE_DELAY_REQ;
		break;
	case RTL8127A_PTP_TX_SYNC_RDY:
	default:
		msgtype = PTP_MSGTYPE_SYNC;
		break;
	}

	ret = rtl8127a_ptp_trx_ts_cmd(ptp,
				      FIELD_PREP(RTL8127A_PTP_TRX_TS_MSGTYPE,
						 msgtype) |
				      RTL8127A_PTP_TRX_TS_EXEC);
	if (ret)
		return ret;

	return rtl8127a_ptp_read_time(ptp, RTL8127A_PTP_TRX_TS_TIME, ts);
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

static void rtl8127a_ptp_tx_complete(struct rtl8127a_ptp *ptp,
				     struct skb_shared_hwtstamps *hwts)
{
	struct sk_buff *skb = ptp->tx_skb;

	ptp->tx_skb = NULL;
	clear_bit_unlock(RTL8127A_PTP_TX_IN_PROGRESS, &ptp->state);

	if (hwts)
		skb_complete_tx_timestamp(skb, hwts);
	else
		kfree_skb(skb);
}

/* Returns true if no TX timestamp is pending anymore */
static bool rtl8127a_ptp_tx_tstamp(struct rtl8127a_ptp *ptp)
{
	struct skb_shared_hwtstamps hwts = {};
	struct timespec64 ts;
	int ret;

	/* Pairs with smp_store_release() in rtl8127a_ptp_txtstamp() */
	if (!smp_load_acquire(&ptp->tx_skb))
		return true;

	mutex_lock(&ptp->lock);

	if (time_is_before_jiffies(ptp->tx_start + RTL8127A_PTP_TX_TIMEOUT)) {
		rtl8127a_ptp_write(ptp, RTL8127A_PTP_INSR,
				   RTL8127A_PTP_INT_TX_TS);
		mutex_unlock(&ptp->lock);

		rtl8127a_ptp_tx_complete(ptp, NULL);
		return true;
	}

	ret = rtl8127a_ptp_read(ptp, RTL8127A_PTP_INSR);
	if (ret < 0 || !(ret & RTL8127A_PTP_INT_TX_TS)) {
		mutex_unlock(&ptp->lock);
		return false;
	}

	ret = rtl8127a_ptp_write(ptp, RTL8127A_PTP_INSR,
				 RTL8127A_PTP_INT_TX_TS);
	if (!ret)
		ret = rtl8127a_ptp_egress_time(ptp, &ts);

	mutex_unlock(&ptp->lock);

	if (ret) {
		rtl8127a_ptp_tx_complete(ptp, NULL);
		return true;
	}

	hwts.hwtstamp = timespec64_to_ktime(ts);
	rtl8127a_ptp_tx_complete(ptp, &hwts);

	return true;
}

static void rtl8127a_ptp_rx_tstamp(struct rtl8127a_ptp *ptp,
				   struct sk_buff *skb)
{
	u8 msgtype = RTL8127A_PTP_SKB_CB(skb)->msgtype;
	struct timespec64 ts;
	int ret;

	mutex_lock(&ptp->lock);
	ret = rtl8127a_ptp_trx_ts_cmd(ptp, RTL8127A_PTP_TRX_TS_SEL_RX |
					   FIELD_PREP(RTL8127A_PTP_TRX_TS_MSGTYPE,
						      msgtype) |
					   RTL8127A_PTP_TRX_TS_EXEC);
	if (!ret)
		ret = rtl8127a_ptp_read_time(ptp, RTL8127A_PTP_TRX_TS_TIME,
					     &ts);
	mutex_unlock(&ptp->lock);

	if (!ret)
		skb_hwtstamps(skb)->hwtstamp = timespec64_to_ktime(ts);

	netif_rx(skb);
}

static long rtl8127a_ptp_do_aux_work(struct ptp_clock_info *info)
{
	struct rtl8127a_ptp *ptp = container_of(info, struct rtl8127a_ptp, info);
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&ptp->rx_queue)))
		rtl8127a_ptp_rx_tstamp(ptp, skb);

	/* Keep polling until the pending TX timestamp is available */
	return rtl8127a_ptp_tx_tstamp(ptp) ? -1 : 0;
}

static const struct ptp_clock_info rtl8127a_ptp_info = {
	.owner		= THIS_MODULE,
	.name		= "RTL8127A PHC",
	.max_adj	= RTL8127A_PTP_MAX_ADJ,
	.adjfine	= rtl8127a_ptp_adjfine,
	.adjtime	= rtl8127a_ptp_adjtime,
	.gettimex64	= rtl8127a_ptp_gettimex64,
	.settime64	= rtl8127a_ptp_settime64,
	.do_aux_work	= rtl8127a_ptp_do_aux_work,
};

static void rtl8127a_ptp_txtstamp(struct mii_timestamper *mii_ts,
				  struct sk_buff *skb, int type)
{
	struct rtl8127a_ptp *ptp = container_of(mii_ts, struct rtl8127a_ptp,
						mii_ts);

	/* Only one TX timestamp can be pending at a time */
	if (READ_ONCE(ptp->tx_type) != HWTSTAMP_TX_ON ||
	    test_and_set_bit_lock(RTL8127A_PTP_TX_IN_PROGRESS, &ptp->state)) {
		kfree_skb(skb);
		return;
	}

	skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;
	ptp->tx_start = jiffies;
	/* Publish tx_start before tx_skb to the aux worker */
	smp_store_release(&ptp->tx_skb, skb);
	ptp_schedule_worker(ptp->clock, 0);
}

static bool rtl8127a_ptp_rxtstamp(struct mii_timestamper *mii_ts,
				  struct sk_buff *skb, int type)
{
	struct rtl8127a_ptp *ptp = container_of(mii_ts, struct rtl8127a_ptp,
						mii_ts);
	struct ptp_header *hdr;
	u8 msgtype;

	if (!READ_ONCE(ptp->rx_enabled))
		return false;

	hdr = ptp_parse_header(skb, type);
	if (!hdr)
		return false;

	/* Only event messages are timestamped by the hardware */
	msgtype = ptp_get_msgtype(hdr, type);
	if (msgtype > PTP_MSGTYPE_PDELAY_RESP)
		return false;

	RTL8127A_PTP_SKB_CB(skb)->msgtype = msgtype;
	skb_queue_tail(&ptp->rx_queue, skb);
	ptp_schedule_worker(ptp->clock, 0);

	return true;
}

static int rtl8127a_ptp_hwtstamp_get(struct mii_timestamper *mii_ts,
				     struct kernel_hwtstamp_config *config)
{
	struct rtl8127a_ptp *ptp = container_of(mii_ts, struct rtl8127a_ptp,
						mii_ts);

	config->tx_type = ptp->tx_type;
	config->rx_filter = ptp->rx_filter;

	return 0;
}

static int rtl8127a_ptp_hwtstamp_set(struct mii_timestamper *mii_ts,
				     struct kernel_hwtstamp_config *config,
				     struct netlink_ext_ack *extack)
{
	struct rtl8127a_ptp *ptp = container_of(mii_ts, struct rtl8127a_ptp,
						mii_ts);
	bool enable = false;
	bool rx_enabled;
	int ret = 0;

	if (config->flags)
		return -EINVAL;

	switch (config->tx_type) {
	case HWTSTAMP_TX_ON:
		enable = true;
		break;
	case HWTSTAMP_TX_OFF:
		break;
	default:
		return -ERANGE;
	}

	switch (config->rx_filter) {
	case HWTSTAMP_FILTER_NONE:
		rx_enabled = false;
		break;
	case HWTSTAMP_FILTER_PTP_V2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ:
		config->rx_filter = HWTSTAMP_FILTER_PTP_V2_EVENT;
		rx_enabled = true;
		enable = true;
		break;
	default:
		return -ERANGE;
	}

	if (ptp->tx_type != config->tx_type ||
	    ptp->rx_filter != config->rx_filter) {
		WRITE_ONCE(ptp->tx_type, config->tx_type);
		ptp->rx_filter = config->rx_filter;
		ret = rtl8127a_ptp_hwtstamp_enable(ptp, enable);
	}
	WRITE_ONCE(ptp->rx_enabled, rx_enabled);

	return ret;
}

static int rtl8127a_ptp_ts_info(struct mii_timestamper *mii_ts,
				struct kernel_ethtool_ts_info *info)
{
	struct rtl8127a_ptp *ptp = container_of(mii_ts, struct rtl8127a_ptp,
						mii_ts);

	info->so_timestamping = SOF_TIMESTAMPING_TX_SOFTWARE |
				SOF_TIMESTAMPING_TX_HARDWARE |
				SOF_TIMESTAMPING_RX_HARDWARE |
				SOF_TIMESTAMPING_RAW_HARDWARE;
	info->phc_index = ptp_clock_index(ptp->clock);
	info->tx_types = BIT(HWTSTAMP_TX_OFF) | BIT(HWTSTAMP_TX_ON);
	info->rx_filters = BIT(HWTSTAMP_FILTER_NONE) |
			   BIT(HWTSTAMP_FILTER_PTP_V2_EVENT) |
			   BIT(HWTSTAMP_FILTER_PTP_V2_L4_EVENT) |
			   BIT(HWTSTAMP_FILTER_PTP_V2_SYNC) |
			   BIT(HWTSTAMP_FILTER_PTP_V2_L4_SYNC) |
			   BIT(HWTSTAMP_FILTER_PTP_V2_DELAY_REQ) |
			   BIT(HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ);

	return 0;
}

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
	ptp->tx_type = HWTSTAMP_TX_OFF;
	ptp->rx_filter = HWTSTAMP_FILTER_NONE;
	skb_queue_head_init(&ptp->rx_queue);

	ret = rtl8127a_ptp_hwtstamp_enable(ptp, false);
	if (ret)
		return ret;

	ptp->clock = ptp_clock_register(&ptp->info, dev);
	if (IS_ERR(ptp->clock))
		return PTR_ERR(ptp->clock);

	ptp->mii_ts.rxtstamp = rtl8127a_ptp_rxtstamp;
	ptp->mii_ts.txtstamp = rtl8127a_ptp_txtstamp;
	ptp->mii_ts.hwtstamp_set = rtl8127a_ptp_hwtstamp_set;
	ptp->mii_ts.hwtstamp_get = rtl8127a_ptp_hwtstamp_get;
	ptp->mii_ts.ts_info = rtl8127a_ptp_ts_info;

	phydev->priv = ptp;
	phydev->mii_ts = &ptp->mii_ts;
	phydev->default_timestamp = true;

	return 0;
}

void rtl8127a_ptp_remove(struct phy_device *phydev)
{
	struct rtl8127a_ptp *ptp = phydev->priv;

	if (!ptp)
		return;

	phydev->mii_ts = NULL;
	phydev->default_timestamp = false;

	rtl8127a_ptp_hwtstamp_enable(ptp, false);
	/* Also stops the aux worker */
	ptp_clock_unregister(ptp->clock);

	if (ptp->tx_skb)
		rtl8127a_ptp_tx_complete(ptp, NULL);
	skb_queue_purge(&ptp->rx_queue);
}
